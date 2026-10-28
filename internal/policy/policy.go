// Package policy provides functions to enforce the baseline security and configuration policy for sandboxes.
// It checks for any changes that could reach or leak from the host during init or rebuild phases.
package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"slices"
	"strings"

	"github.com/evsor/agent-sandbox/internal/config"
	"github.com/evsor/agent-sandbox/internal/policy/claude"
)

var mountTargets = []string{"/workspace", claude.StateTarget}

var denyGroups = []string{"private", "loopback", "link-local", "metadata", "multicast"}

var groups = []string{"public", "private", "loopback", "link-local", "metadata", "multicast", hostGroup, "*"}

const hostGroup = "host"

const (
	actionAllow = "allow"
	actionDeny  = "deny"
	egress      = "egress"
)

const (
	allowProtocol = "tcp"
	allowPort     = "443"
)

const (
	namedMount = "named"
	diskKind   = "disk"
)

const (
	wantSecurity = "restricted"
	wantUser     = "node"
)

// DestKind represents the kind of network destination.
type DestKind string

const (
	kindGroup   DestKind = "group"
	kindDomain  DestKind = "domain"
	kindSuffix  DestKind = "suffix"
	kindIP      DestKind = "ip"
	kindCIDR    DestKind = "cidr"
	kindUnknown DestKind = "unknown"
)

// ErrPolicy is returned when a policy violation is detected.
var ErrPolicy = errors.New("policy violation")

const authVarsNotAllowed = "agent credential and endpoint variables are not allowed"

// Spec is a sandbox spec defined by the sandbox.toml or live configuration.
type Spec struct {
	User           string
	Security       string
	Mounts         []Mount
	DefaultEgress  string
	DefaultIngress string
	Rules          []Rule
	Strict         bool
	InterceptTLS   bool
	PublishedPorts int
	Secrets        []Secret
	EnvNames       []string
	Strings        []string // every config string except secret values, scanned for "${"
	Image          string   // informational: the check doesn't judge it
}

// Mount is a guest mount. Type is "named" for named volumes and Kind their volume kind ("disk", "dir").
type Mount struct {
	Type   string
	Name   string
	Target string
	Kind   string
	Nosuid bool
	Nodev  bool
}

// Rule is a network rule. Dest is normalized: a group the SDK knows, a domain, a .suffix, an IP or a CIDR.
type Rule struct {
	Action    string
	Direction string
	DestKind  DestKind
	Dest      string
	Protocols []string
	Ports     []string
}

// Secret is a declared secret, without its value.
type Secret struct {
	Name         string
	Hosts        []string
	HeaderFields []string
	Placeholder  string
}

// FromConfig builds a Spec from the loaded sandbox.toml and its raw bytes.
func FromConfig(cfg *config.Config, raw []byte) Spec {
	spec := Spec{
		User:           cfg.User,
		Security:       cfg.Security,
		DefaultEgress:  cfg.Network.DefaultEgress,
		DefaultIngress: cfg.Network.DefaultIngress,
		Strict:         cfg.Network.Strict,
		InterceptTLS:   cfg.Network.InterceptTLS,
		Strings:        []string{string(raw)},
		Image:          cfg.Image,
	}

	for _, v := range cfg.Volumes {
		spec.Mounts = append(spec.Mounts, Mount{
			Type: namedMount, Name: v.Name, Target: v.Target, Kind: v.Kind, Nosuid: v.Nosuid, Nodev: v.Nodev,
		})
	}

	for _, r := range cfg.Network.Rules {
		kind, dest := classify(r.Destination)
		rule := Rule{Action: r.Action, Direction: r.Direction, DestKind: kind, Dest: dest}

		if r.Protocol != "" {
			rule.Protocols = []string{r.Protocol}
		}

		if r.Port != "" {
			rule.Ports = []string{r.Port}
		}

		spec.Rules = append(spec.Rules, rule)
	}

	for _, s := range cfg.Secrets {
		spec.Secrets = append(spec.Secrets, Secret{
			Name: s.Name, Hosts: s.Allow, HeaderFields: s.HeaderFields, Placeholder: s.Placeholder,
		})
	}

	for _, entry := range cfg.Env {
		name, _, _ := strings.Cut(entry, "=")
		spec.EnvNames = append(spec.EnvNames, name)
	}

	return spec
}

// classify sorts a sandbox.toml destination the way the SDK does.
func classify(dest string) (DestKind, string) {
	if group, ok := knownGroup(dest); ok {
		return kindGroup, group
	}

	switch {
	case dest == "":
		return kindUnknown, dest // the SDK reads a missing destination as any
	case net.ParseIP(dest) != nil:
		return kindIP, dest
	case strings.Contains(dest, "/"):
		return kindCIDR, dest
	case strings.HasPrefix(dest, "."):
		return kindSuffix, dest
	default:
		return kindDomain, dest
	}
}

// knownGroup normalizes a group name, which the SDK also accepts as link_local, and reports whether the SDK knows it.
func knownGroup(name string) (string, bool) {
	name = strings.ReplaceAll(name, "_", "-")

	return name, slices.Contains(groups, name)
}

// Check returns every violation in spec, joined, or nil.
func Check(spec Spec) error {
	var errs []error

	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("%w: "+format, append([]any{ErrPolicy}, args...)...))
	}

	for _, s := range spec.Strings {
		if strings.Contains(s, "${") {
			fail(`"${" in the config: msb would expand it from the host environment`)

			break
		}
	}

	checkMounts(spec.Mounts, fail)
	checkNetwork(spec, fail)
	checkSecrets(spec, fail)

	if spec.Security != wantSecurity {
		fail("security is %q, want %s", spec.Security, wantSecurity)
	}

	if spec.User != wantUser {
		fail("user is %q, want %s", spec.User, wantUser)
	}

	return errors.Join(errs...)
}

func checkMounts(mounts []Mount, fail func(string, ...any)) {
	var targets []string

	for _, m := range mounts {
		targets = append(targets, m.Target)

		if m.Type != namedMount || m.Kind != diskKind {
			fail("mount %s: want a named disk volume, got %s %s", m.Target, m.Type, m.Kind)
		}

		if !m.Nosuid || !m.Nodev {
			fail("mount %s: want nosuid and nodev", m.Target)
		}
	}

	slices.Sort(targets)

	want := slices.Clone(mountTargets)
	slices.Sort(want)

	if !slices.Equal(targets, want) {
		fail("mounts are %v, want exactly %v", targets, want)
	}
}

func checkNetwork(spec Spec, fail func(string, ...any)) {
	if spec.DefaultEgress != actionDeny || spec.DefaultIngress != actionDeny {
		fail("default egress/ingress are %q/%q, want deny/deny", spec.DefaultEgress, spec.DefaultIngress)
	}

	if !spec.Strict || !spec.InterceptTLS {
		fail("strict and TLS interception must both be on")
	}

	if spec.PublishedPorts > 0 {
		fail("%d published ports, want none", spec.PublishedPorts)
	}

	denied := checkRules(spec.Rules, fail)

	for _, g := range denyGroups {
		if !denied[g] {
			fail("no egress deny for %s before the allows", g)
		}
	}
}

// checkRules checks each rule and returns the groups denied before the first allow.
func checkRules(rules []Rule, fail func(string, ...any)) map[string]bool {
	denied := map[string]bool{}
	seenAllow := false

	for i, r := range rules {
		if r.DestKind == kindUnknown {
			fail("rule %d: destination %q is not one the check knows", i, r.Dest)
		}

		if r.DestKind == kindGroup && r.Dest == hostGroup {
			fail("rule %d: destination host: allowing it opens the host and forwards any DNS name upstream; denying it breaks name resolution", i)
		}

		switch r.Action {
		case actionDeny:
			plain := r.Direction == egress && len(r.Protocols) == 0 && len(r.Ports) == 0
			if !seenAllow && plain && r.DestKind == kindGroup {
				denied[r.Dest] = true
			}
		case actionAllow:
			seenAllow = true

			checkAllow(i, r, fail)
		default:
			fail("rule %d: unknown action %q", i, r.Action)
		}
	}

	return denied
}

func checkAllow(i int, r Rule, fail func(string, ...any)) {
	if r.Direction != egress {
		fail("rule %d: allow must be egress, got %q", i, r.Direction)
	}

	if !slices.Equal(r.Protocols, []string{allowProtocol}) || !slices.Equal(r.Ports, []string{allowPort}) {
		fail("rule %d: allow %s must be %s:%s only", i, r.Dest, allowProtocol, allowPort)
	}

	switch r.DestKind { //nolint:exhaustive // every other kind, and any kind added later, fails in default
	case kindDomain:
		if strings.Contains(r.Dest, "*") {
			fail("rule %d: %s: write a wildcard as a .suffix", i, r.Dest)
		}
	case kindSuffix: // the SDK's wildcard: ".example.com" matches it and its subdomains
		if !narrowSuffix(strings.TrimPrefix(r.Dest, ".")) {
			fail("rule %d: suffix %s needs at least two labels, none empty and none holding \"*\"", i, r.Dest)
		}
	default:
		fail("rule %d: allow must name a host, got %s %s", i, r.DestKind, r.Dest)
	}
}

func checkSecrets(spec Spec, fail func(string, ...any)) {
	for _, s := range spec.Secrets {
		if len(s.Hosts) == 0 || len(s.HeaderFields) == 0 {
			fail("secret %s: needs hosts and header_fields, or a host that echoes headers could hand the real value to the guest", s.Name)
		}

		for _, host := range s.Hosts {
			if !boundHost(host) {
				fail("secret %s: host %q: name a host, or a *.suffix of at least two labels, none empty and none holding \"*\"", s.Name, host)
			}
		}

		if claude.IsAgentAuthVar(s.Name) {
			fail("secret %s: %s", s.Name, authVarsNotAllowed)
		}
	}

	for _, name := range spec.EnvNames {
		if claude.IsAgentAuthVar(name) {
			fail("env %s: %s", name, authVarsNotAllowed)
		}
	}
}

// boundHost reports whether a secret's host binds it: an exact host, or a "*.suffix" wildcard narrow enough to name a site. The SDK
// reads "*" as any host at all.
func boundHost(host string) bool {
	if suffix, ok := strings.CutPrefix(host, "*."); ok {
		return narrowSuffix(suffix)
	}

	return host != "" && !strings.Contains(host, "*")
}

// narrowSuffix reports whether a domain suffix, without its leading dot, has at least two labels, none empty or holding a "*", so it
// can't match a whole top-level domain.
func narrowSuffix(suffix string) bool {
	labels := strings.Split(suffix, ".")

	return len(labels) >= 2 && !slices.Contains(labels, "") && !strings.Contains(suffix, "*")
}

// CheckManaged checks fsys, the agent's managed directory exported from the built image: its settings and the modes of every entry. The
// result wraps ErrPolicy as a whole, a directory it can't read included.
func CheckManaged(fsys fs.FS) error {
	if err := errors.Join(claude.CheckSettings(fsys), claude.CheckModes(fsys)); err != nil {
		return fmt.Errorf("%w: %w", ErrPolicy, err)
	}

	return nil
}

// CheckImageEnv checks the image's env, "NAME=value" entries as docker image inspect lists them, for agent credential and endpoint
// variables. Messages name the variable, never its value.
func CheckImageEnv(env []string) error {
	var errs []error

	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if claude.IsAgentAuthVar(name) {
			errs = append(errs, fmt.Errorf("%w: image env %s: %s", ErrPolicy, name, authVarsNotAllowed))
		}
	}

	return errors.Join(errs...)
}
