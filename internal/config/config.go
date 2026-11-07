// Package config loads the sandbox spec from sandbox.toml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/viper"
)

const egress = "egress"

// Config maps the TOML keys to Go struct fields.
type Config struct {
	Name        string   `mapstructure:"name"`
	Image       string   `mapstructure:"image"`
	CPUs        uint8    `mapstructure:"cpus"`
	MemoryMiB   uint32   `mapstructure:"memory_mib"`
	RootDiskMiB uint32   `mapstructure:"root_disk_mib"`
	User        string   `mapstructure:"user"`
	Workdir     string   `mapstructure:"workdir"`
	Shell       string   `mapstructure:"shell"`
	Security    string   `mapstructure:"security"`
	Env         []string `mapstructure:"env"` // NAME=value; a list because viper lowercases map keys
	Volumes     []Volume `mapstructure:"volumes"`
	Network     Network  `mapstructure:"network"`
	Secrets     []Secret `mapstructure:"secrets"`
}

// Volume is a named volume mounted at Target.
type Volume struct {
	Name    string `mapstructure:"name"`
	Target  string `mapstructure:"target"`
	Kind    string `mapstructure:"kind"`
	SizeMiB uint32 `mapstructure:"size_mib"`
	Nosuid  bool   `mapstructure:"nosuid"`
	Nodev   bool   `mapstructure:"nodev"`
}

// Network is the egress and ingress policy.
type Network struct {
	DefaultEgress  string   `mapstructure:"default_egress"`
	DefaultIngress string   `mapstructure:"default_ingress"`
	Strict         bool     `mapstructure:"strict"`
	InterceptTLS   bool     `mapstructure:"intercept_tls"`
	Deny           []string `mapstructure:"deny"`          // egress groups
	AllowDomains   []string `mapstructure:"allow_domains"` // hosts and .suffixes, on tcp:443
	AllowIPs       []string `mapstructure:"allow_ips"`     // addresses and CIDR ranges, on tcp:443
}

// Rule is one network policy rule.
type Rule struct {
	Action      string
	Direction   string
	Destination string
	Protocol    string
	Port        string
}

// Rules expands the lists into policy rules. The first match wins, so the denies come first.
func (n Network) Rules() []Rule {
	rules := make([]Rule, 0, len(n.Deny)+len(n.AllowDomains)+len(n.AllowIPs))

	for _, dest := range n.Deny {
		rules = append(rules, Rule{Action: "deny", Direction: egress, Destination: dest})
	}

	for _, dest := range slices.Concat(n.AllowDomains, n.AllowIPs) {
		rules = append(rules, Rule{Action: "allow", Direction: egress, Destination: dest, Protocol: "tcp", Port: "443"})
	}

	return rules
}

// validate keeps each allow list to its own kind: the SDK reads a destination by its form, so an address in allow_domains would
// otherwise become an address allow unnoticed.
func (n Network) validate() error {
	for _, dest := range n.AllowDomains {
		if isAddress(dest) || strings.Contains(dest, "/") {
			return fmt.Errorf("allow_domains entry %q: want a host or a .suffix", dest)
		}
	}

	for _, dest := range n.AllowIPs {
		if !isAddress(dest) || strings.Contains(dest, "%") { // the SDK reads an address with a zone as a name
			return fmt.Errorf("allow_ips entry %q: want an address or a CIDR range", dest)
		}
	}

	return nil
}

// isAddress reports whether dest is an IP address or a CIDR range.
func isAddress(dest string) bool {
	if _, err := netip.ParseAddr(dest); err == nil {
		return true
	}

	_, err := netip.ParsePrefix(dest)

	return err == nil
}

// Secret declares a credential.
type Secret struct {
	Name            string   `mapstructure:"name"`
	Allow           []string `mapstructure:"allow"`
	Placeholder     string   `mapstructure:"placeholder"`
	HeaderFields    []string `mapstructure:"header_fields"`
	Passthrough     []string `mapstructure:"passthrough"`
	ViolationAction string   `mapstructure:"violation_action"`
}

// To be safe for the ssh config and file paths.
var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// ValidName reports whether name can name the sandbox.
func ValidName(name string) bool { return validName.MatchString(name) }

// Load reads the TOML file at path and returns its config and raw bytes, which the policy check scans; see Parse.
func Load(path string) (*Config, []byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the spec of the checkout sbx runs from
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	cfg, err := Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}

	return cfg, raw, nil
}

// Parse the TOML spec.
func Parse(raw []byte) (*Config, error) {
	v := viper.New()
	v.SetConfigType("toml")

	if err := v.ReadConfig(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}

	var cfg Config
	if err := v.UnmarshalExact(&cfg); err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}

	if cfg.Image == "" {
		return nil, errors.New("image is required")
	}

	if !ValidName(cfg.Name) {
		return nil, fmt.Errorf("name %q: want lowercase letters, digits and dashes", cfg.Name)
	}

	if _, err := cfg.EnvMap(); err != nil {
		return nil, err
	}

	if err := cfg.Network.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// EnvMap returns Env as a map.
func (c *Config) EnvMap() (map[string]string, error) {
	env := make(map[string]string, len(c.Env))

	for _, entry := range c.Env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("env entry %q: want NAME=value", entry)
		}

		env[name] = value
	}

	return env, nil
}

// SecretNames returns the declared secret names.
func (c *Config) SecretNames() []string {
	names := make([]string, 0, len(c.Secrets))
	for _, s := range c.Secrets {
		names = append(names, s.Name)
	}

	return names
}

// ErrSecretUnset reports declared secrets whose host variable is empty.
var ErrSecretUnset = errors.New("secret not set in the environment")

// SecretValues reads each declared secret's value with getenv and fails, naming every missing one, if any is empty.
func SecretValues(names []string, getenv func(string) string) (map[string]string, error) {
	values := make(map[string]string, len(names))

	var missing []string

	for _, name := range names {
		value := getenv(name)
		if value == "" {
			missing = append(missing, name)

			continue
		}

		values[name] = value
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrSecretUnset, strings.Join(missing, ", "))
	}

	return values, nil
}
