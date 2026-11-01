// Package policy provides functions to enforce the baseline security and configuration policy for sandboxes.
// It checks for any changes that could reach or leak from the host during init or rebuild phases, and checks what commands print in the
// running sandbox.
package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
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

// The widest ranges an address allow may name: about a provider's block, not a share of the internet.
const (
	minPrefix4 = 16
	minPrefix6 = 32
)

// ipv6Unicast is the part of IPv6 assigned for public use. Outside it are the forms that stand for IPv4 addresses, such as NAT64's
// 64:ff9b::/96, which would open all of IPv4 at once.
var ipv6Unicast = netip.MustParsePrefix("2000::/3")

// reservedRanges are the special-purpose ranges that the remaining checks let through.
var reservedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

const (
	namedMount = "named"
	diskKind   = "disk"
)

const wantSecurity = "restricted"

// NodeUser is the user everything runs as in the sandbox.
const NodeUser = "node"

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
	Image          string   // informational: the check ignores it
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

	for _, r := range cfg.Network.Rules() {
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

	spec.EnvNames = envNames(cfg.Env)

	return spec
}

// envNames returns the names of "NAME=value" entries.
func envNames(entries []string) []string {
	var names []string

	for _, entry := range entries {
		name, _, _ := strings.Cut(entry, "=")
		names = append(names, name)
	}

	return names
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

// violations collects what a check finds, each wrapping ErrPolicy.
type violations []error

func (v *violations) fail(format string, args ...any) {
	*v = append(*v, fmt.Errorf("%w: "+format, append([]any{ErrPolicy}, args...)...))
}

// Check returns every violation in spec, joined, or nil.
func Check(spec Spec) error {
	var found violations

	fail := found.fail

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

	if spec.User != NodeUser {
		fail("user is %q, want %s", spec.User, NodeUser)
	}

	return errors.Join(found...)
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
			if checkDeny(i, r, fail) && !seenAllow {
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

// checkDeny checks a deny and reports whether it covers a whole group: every egress port and protocol.
func checkDeny(i int, r Rule, fail func(string, ...any)) bool {
	if r.DestKind != kindGroup && r.DestKind != kindUnknown { // an unknown destination has already failed
		fail("rule %d: deny must name a group, got %s %s", i, r.DestKind, r.Dest)
	}

	return r.DestKind == kindGroup && r.Direction == egress && len(r.Protocols) == 0 && len(r.Ports) == 0
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
	case kindIP, kindCIDR:
		if !narrowPublic(r.Dest) {
			fail("rule %d: %s: want a public address, or a public range of at least /%d for IPv4 and /%d for IPv6", i, r.Dest, minPrefix4, minPrefix6)
		}
	default:
		fail("rule %d: allow must name a host or a public address, got %s %s", i, r.DestKind, r.Dest)
	}
}

// narrowPublic reports whether dest, an address or a CIDR range, is public and small enough to stand for a service rather than a large
// part of the internet. An address allow isn't tied to a name, so it opens every site served from the range. The denies aren't relied on
// for non-public addresses: nothing shows the private group alone covers the gateway.
func narrowPublic(dest string) bool {
	prefix, err := netip.ParsePrefix(dest)
	if err != nil {
		addr, err := netip.ParseAddr(dest)
		if err != nil || addr.Zone() != "" {
			return false
		}

		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	prefix = prefix.Masked()
	addr := prefix.Addr()

	if addr.Is4() {
		if prefix.Bits() < minPrefix4 || !addr.IsGlobalUnicast() || addr.IsPrivate() {
			return false
		}
	} else if prefix.Bits() < minPrefix6 || !ipv6Unicast.Contains(addr) {
		return false
	}

	return !slices.ContainsFunc(reservedRanges, prefix.Overlaps)
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

	checkEnvNames("env", spec.EnvNames, fail)
}

// checkEnvNames fails on agent credential and endpoint variables. Messages name the variable, never its value.
func checkEnvNames(kind string, names []string, fail func(string, ...any)) {
	for _, name := range names {
		if claude.IsAgentAuthVar(name) {
			fail("%s %s: %s", kind, name, authVarsNotAllowed)
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
// variables.
func CheckImageEnv(env []string) error {
	var found violations

	checkEnvNames("image env", envNames(env), found.fail)

	return errors.Join(found...)
}
