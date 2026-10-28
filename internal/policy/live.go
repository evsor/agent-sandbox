// live checks the running sandbox's configuration against the policy.

package policy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// liveConfig is the part of SandboxHandle.ConfigJSON().
type liveConfig struct {
	Image struct {
		Oci struct {
			Reference string `json:"reference"`
		} `json:"Oci"`
	} `json:"image"`
	SecurityProfile string `json:"security_profile"`
	Runtime         struct {
		User string `json:"user"`
	} `json:"runtime"`
	Env []struct {
		Key string `json:"key"`
	} `json:"env"`
	Mounts  []liveMount       `json:"mounts"`
	Ports   []json.RawMessage `json:"ports"`
	Network struct {
		Ports  []json.RawMessage `json:"ports"`
		Strict bool              `json:"strict"`
		TLS    struct {
			Enabled bool `json:"enabled"`
		} `json:"tls"`
		Policy struct {
			DefaultEgress  string     `json:"default_egress"`
			DefaultIngress string     `json:"default_ingress"`
			Rules          []liveRule `json:"rules"`
		} `json:"policy"`
		Secrets struct {
			Secrets []liveSecret `json:"secrets"`
		} `json:"secrets"`
	} `json:"network"`
}

type liveMount struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Guest   string `json:"guest"`
	Options struct {
		Nosuid bool `json:"nosuid"`
		Nodev  bool `json:"nodev"`
	} `json:"options"`
}

type liveRule struct {
	Action      string          `json:"action"`
	Direction   string          `json:"direction"`
	Destination json.RawMessage `json:"destination"`
	Protocols   []string        `json:"protocols"`
	Ports       []struct {
		Start int `json:"start"`
		End   int `json:"end"`
	} `json:"ports"`
}

type liveSecret struct {
	EnvVar       string `json:"env_var"`
	Placeholder  string `json:"placeholder"`
	AllowedHosts []struct {
		Exact    string `json:"exact"`
		Wildcard string `json:"wildcard"`
	} `json:"allowed_hosts"`
	Substitution struct {
		HeaderFields []string `json:"header_fields"`
	} `json:"substitution"`
}

// FromConfigJSON builds a Spec from the live sandbox config.
func FromConfigJSON(raw []byte, volumeKind func(name string) (string, error)) (Spec, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Spec{}, fmt.Errorf("parsing the live config: %w", err)
	}

	var live liveConfig
	if err := json.Unmarshal(raw, &live); err != nil {
		return Spec{}, fmt.Errorf("reading the live config: %w", err)
	}

	network := live.Network
	spec := Spec{
		User:           live.Runtime.User,
		Security:       live.SecurityProfile,
		DefaultEgress:  network.Policy.DefaultEgress,
		DefaultIngress: network.Policy.DefaultIngress,
		Strict:         network.Strict,
		InterceptTLS:   network.TLS.Enabled,
		PublishedPorts: len(live.Ports) + len(network.Ports),
		Strings:        configStrings(doc),
		Image:          live.Image.Oci.Reference,
	}

	for _, m := range live.Mounts {
		mount, err := m.mount(volumeKind)
		if err != nil {
			return Spec{}, err
		}

		spec.Mounts = append(spec.Mounts, mount)
	}

	for _, r := range network.Policy.Rules {
		spec.Rules = append(spec.Rules, r.rule())
	}

	for _, s := range network.Secrets.Secrets {
		secret, err := s.secret()
		if err != nil {
			return Spec{}, err
		}

		spec.Secrets = append(spec.Secrets, secret)
	}

	for _, e := range live.Env {
		spec.EnvNames = append(spec.EnvNames, e.Key)
	}

	return spec, nil
}

// mount converts m, looking up a named volume's kind with volumeKind when it isn't nil.
func (m liveMount) mount(volumeKind func(name string) (string, error)) (Mount, error) {
	mount := Mount{
		Type: strings.ToLower(m.Type), Name: m.Name, Target: m.Guest,
		Nosuid: m.Options.Nosuid, Nodev: m.Options.Nodev,
	}

	if volumeKind != nil && mount.Type == namedMount {
		kind, err := volumeKind(m.Name)
		if err != nil {
			return Mount{}, fmt.Errorf("volume %s: %w", m.Name, err)
		}

		mount.Kind = kind
	}

	return mount, nil
}

// rule converts r, writing its port ranges the way sandbox.toml does: "443", or "8000-9000".
func (r liveRule) rule() Rule {
	kind, dest := liveDestination(r.Destination)
	rule := Rule{Action: r.Action, Direction: r.Direction, DestKind: kind, Dest: dest}

	if len(r.Protocols) > 0 { // otherwise nil, as FromConfig leaves a rule for any protocol
		rule.Protocols = r.Protocols
	}

	for _, p := range r.Ports {
		if p.Start == p.End {
			rule.Ports = append(rule.Ports, strconv.Itoa(p.Start))
		} else {
			rule.Ports = append(rule.Ports, fmt.Sprintf("%d-%d", p.Start, p.End))
		}
	}

	return rule
}

// secret converts s. An allowed host that isn't exactly one exact host or one wildcard is an error.
func (s liveSecret) secret() (Secret, error) {
	secret := Secret{Name: s.EnvVar, HeaderFields: s.Substitution.HeaderFields, Placeholder: s.Placeholder}

	for _, h := range s.AllowedHosts {
		if (h.Exact == "") == (h.Wildcard == "") {
			return Secret{}, fmt.Errorf("secret %s: an allowed host of an unknown shape", s.EnvVar)
		}

		secret.Hosts = append(secret.Hosts, h.Exact+h.Wildcard)
	}

	return secret, nil
}

// liveDestination normalizes a stored destination the way classify does a sandbox.toml one.
func liveDestination(raw json.RawMessage) (DestKind, string) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "any" {
			return kindGroup, "*"
		}

		return kindUnknown, s
	}

	var obj map[string]string
	if json.Unmarshal(raw, &obj) != nil || len(obj) != 1 {
		return kindUnknown, string(raw)
	}

	var key, value string
	for k, v := range obj {
		key, value = k, v
	}

	if value == "" { // as classify reads an empty sandbox.toml destination
		return kindUnknown, key
	}

	switch key {
	case "group":
		if group, ok := knownGroup(value); ok {
			return kindGroup, group
		}

		return kindUnknown, value
	case "domain":
		return kindDomain, value
	case "domain_suffix":
		return kindSuffix, "." + value
	case "cidr":
		return kindCIDR, value
	default:
		return kindUnknown, key
	}
}

// configStrings returns every string in the decoded config, keys included, except secret values.
func configStrings(doc any) []string {
	var out []string

	var walk func(v any)

	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			_, isSecret := t["env_var"]
			for k, e := range t {
				out = append(out, k)

				if isSecret && k == "value" {
					continue
				}

				walk(e)
			}
		}
	}

	walk(doc)

	return out
}
