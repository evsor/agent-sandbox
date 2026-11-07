// Tests for the generic rules: one case per rule in Check and CheckImageEnv, the repo's own sandbox.toml and managed settings
// passing, and FromConfig mapping every field Check uses (live_test.go tests FromConfigJSON against it).
//
// They run with make test, so in CI on every PR; a failing case fails the build.

package policy

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/evsor/agent-sandbox/internal/config"
	"github.com/evsor/agent-sandbox/internal/policy/claude"
)

// authHeader is the header field the test secrets substitute into.
const authHeader = "authorization"

// validSpec is a spec that passes every rule.
func validSpec() Spec {
	spec := Spec{
		User:           "node",
		Security:       "restricted",
		DefaultEgress:  actionDeny,
		DefaultIngress: actionDeny,
		Strict:         true,
		InterceptTLS:   true,
		Mounts: []Mount{
			{Type: namedMount, Name: "ws", Target: "/workspace", Kind: diskKind, Nosuid: true, Nodev: true},
			{Type: namedMount, Name: "st", Target: "/home/node/claude-state", Kind: diskKind, Nosuid: true, Nodev: true},
		},
		Secrets:  []Secret{{Name: patSecret, Hosts: []string{patHost}, HeaderFields: []string{authHeader}, Passthrough: []string{anthropicHost}}},
		EnvNames: []string{"GH_TOKEN"},
		Strings:  []string{"plain"},
	}

	for _, g := range denyGroups {
		spec.Rules = append(spec.Rules, Rule{Action: actionDeny, Direction: egress, DestKind: kindGroup, Dest: g})
	}

	spec.Rules = append(spec.Rules,
		allow(kindDomain, anthropicHost),
		allow(kindSuffix, ".githubusercontent.com"))

	return spec
}

// firstAllow is the index of validSpec's first allow rule, after its deny groups.
var firstAllow = len(denyGroups)

// notPublic is the check's message for an address allow it refuses.
const notPublic = "want a public address"

func allow(kind DestKind, dest string) Rule {
	return Rule{Action: actionAllow, Direction: egress, DestKind: kind, Dest: dest, Protocols: []string{"tcp"}, Ports: []string{"443"}}
}

func TestCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(s *Spec)
		wantErr string
	}{
		{name: "valid spec passes", mutate: func(*Spec) {}},
		{name: "${ anywhere", mutate: func(s *Spec) { s.Strings = append(s.Strings, "x${HOME}") }, wantErr: `"${"`},
		{name: "bind mount", mutate: func(s *Spec) { s.Mounts[0].Type = "bind" }, wantErr: "want a named disk volume"},
		{name: "dir volume", mutate: func(s *Spec) { s.Mounts[0].Kind = "dir" }, wantErr: "want a named disk volume"},
		{name: "dotted target", mutate: func(s *Spec) { s.Mounts[1].Target = "/home/node/.claude" }, wantErr: "want exactly"},
		{name: "missing nosuid", mutate: func(s *Spec) { s.Mounts[0].Nosuid = false }, wantErr: "want nosuid and nodev"},
		{name: "missing nodev", mutate: func(s *Spec) { s.Mounts[1].Nodev = false }, wantErr: "want nosuid and nodev"},
		{name: "a third mount", mutate: func(s *Spec) {
			s.Mounts = append(s.Mounts, Mount{Type: namedMount, Target: "/data", Kind: diskKind, Nosuid: true, Nodev: true})
		}, wantErr: "want exactly"},
		{name: "default egress allow", mutate: func(s *Spec) { s.DefaultEgress = "allow" }, wantErr: "want deny/deny"},
		{name: "default ingress allow", mutate: func(s *Spec) { s.DefaultIngress = "allow" }, wantErr: "want deny/deny"},
		{name: "strict off", mutate: func(s *Spec) { s.Strict = false }, wantErr: "strict and TLS"},
		{name: "TLS interception off", mutate: func(s *Spec) { s.InterceptTLS = false }, wantErr: "strict and TLS"},
		{name: "published port", mutate: func(s *Spec) { s.PublishedPorts = 1 }, wantErr: "published ports"},
		{name: "deny host", mutate: func(s *Spec) {
			s.Rules = append([]Rule{{Action: actionDeny, Direction: egress, DestKind: kindGroup, Dest: hostGroup}}, s.Rules...)
		}, wantErr: "destination host"},
		{name: "dns allow", mutate: func(s *Spec) {
			s.Rules = append(s.Rules, Rule{Action: actionAllow, Direction: egress, DestKind: kindGroup, Dest: hostGroup, Protocols: []string{"udp", "tcp"}, Ports: []string{"53"}})
		}, wantErr: "destination host"},
		{name: "missing deny group", mutate: func(s *Spec) { s.Rules = s.Rules[1:] }, wantErr: "no egress deny for private"},
		{name: "deny group after an allow", mutate: func(s *Spec) {
			s.Rules = append([]Rule{allow(kindDomain, "example.com")}, s.Rules...)
		}, wantErr: "before the allows"},
		{name: "deny group limited to a port", mutate: func(s *Spec) { s.Rules[0].Ports = []string{"443"} }, wantErr: "no egress deny for private"},
		{name: "allow on port 80", mutate: func(s *Spec) { s.Rules[firstAllow].Ports = []string{"80"} }, wantErr: "tcp:443 only"},
		{name: "allow on udp", mutate: func(s *Spec) { s.Rules[firstAllow].Protocols = []string{"udp"} }, wantErr: "tcp:443 only"},
		{name: "allow on any protocol", mutate: func(s *Spec) { s.Rules[firstAllow].Protocols = nil }, wantErr: "tcp:443 only"},
		{name: "allow ingress", mutate: func(s *Spec) { s.Rules[firstAllow].Direction = "ingress" }, wantErr: "must be egress"},
		{name: "allow a group", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindGroup, "public")) }, wantErr: "must name a host"},
		{name: "allow a public IP", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "1.1.1.1")) }},
		{name: "allow a public IPv6 address", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "2606:4700:4700::1111")) }},
		{name: "allow a public range", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "140.82.112.0/20")) }},
		{name: "allow the widest IPv4 range", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "140.82.0.0/16")) }},
		{name: "allow the widest IPv6 range", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "2606:4700::/32")) }},
		{name: "allow every address", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "0.0.0.0/0")) }, wantErr: notPublic},
		{name: "allow too wide an IPv4 range", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "140.82.0.0/15")) }, wantErr: notPublic},
		{name: "allow too wide an IPv6 range", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "2606::/16")) }, wantErr: notPublic},
		{name: "allow a private IP", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "10.0.0.1")) }, wantErr: notPublic},
		{name: "allow a private range", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "192.168.0.0/24")) }, wantErr: notPublic},
		{name: "allow a private range by a host inside it", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "10.0.0.1/16")) }, wantErr: notPublic},
		{name: "allow a loopback IP", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "127.0.0.1")) }, wantErr: notPublic},
		{name: "allow the metadata IP", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "169.254.169.254")) }, wantErr: notPublic},
		{name: "allow a multicast IP", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "224.0.0.1")) }, wantErr: notPublic},
		{name: "allow a private IP mapped into IPv6", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "::ffff:10.0.0.1")) }, wantErr: notPublic},
		{name: "allow a private IPv6 address", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "fd00::1")) }, wantErr: notPublic},
		{name: "allow NAT64", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "64:ff9b::/96")) }, wantErr: notPublic},
		{name: "allow the NAT64 block", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "64:ff9b::/32")) }, wantErr: notPublic},
		{name: "allow shared address space", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "100.64.0.0/16")) }, wantErr: notPublic},
		{name: "allow the benchmarking range", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "198.18.0.0/16")) }, wantErr: notPublic},
		{name: "allow a range holding a reserved block", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "192.0.0.0/16")) }, wantErr: notPublic},
		{name: "allow a reserved address", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "240.0.0.1")) }, wantErr: notPublic},
		{name: "allow this network", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "0.1.0.0/16")) }, wantErr: notPublic},
		{name: "allow documentation IPv6", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "2001:db8::1")) }, wantErr: notPublic},
		{name: "allow 6to4", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "2002:a00:1::/48")) }, wantErr: notPublic},
		{name: "allow an IPv4-compatible address", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "::a00:1")) }, wantErr: notPublic},
		{name: "allow a zoned address", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindIP, "2606:4700::1%eth0")) }, wantErr: notPublic},
		{name: "deny a domain", mutate: func(s *Spec) {
			s.Rules = append([]Rule{{Action: actionDeny, Direction: egress, DestKind: kindDomain, Dest: "example.com"}}, s.Rules...)
		}, wantErr: "deny must name a group"},
		{name: "allow an unparsable range", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindCIDR, "not/a-range")) }, wantErr: notPublic},
		{name: "allow a star domain", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindDomain, "*.example.com")) }, wantErr: "as a .suffix"},
		{name: "one-label suffix", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindSuffix, ".com")) }, wantErr: "at least two labels"},
		{name: "suffix with an empty first label", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindSuffix, "..com")) }, wantErr: "suffix ..com needs"},
		{name: "suffix with a star label", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindSuffix, ".*.github.com")) }, wantErr: "suffix .*.github.com needs"},
		{name: "suffix with an empty last label", mutate: func(s *Spec) { s.Rules = append(s.Rules, allow(kindSuffix, ".com.")) }, wantErr: "suffix .com. needs"},
		{name: "rule without a destination", mutate: func(s *Spec) {
			s.Rules = append(s.Rules, Rule{Action: actionAllow, Direction: egress, DestKind: kindUnknown, Protocols: []string{"tcp"}, Ports: []string{"443"}})
		}, wantErr: "not one the check knows"},
		{name: "unknown action", mutate: func(s *Spec) { s.Rules[firstAllow].Action = "log" }, wantErr: "unknown action"},
		{name: "secret without header_fields", mutate: func(s *Spec) { s.Secrets[0].HeaderFields = nil }, wantErr: "needs hosts and header_fields"},
		{name: "secret without hosts", mutate: func(s *Spec) { s.Secrets[0].Hosts = nil }, wantErr: "needs hosts and header_fields"},
		{name: "secret for a narrow wildcard", mutate: func(s *Spec) { s.Secrets[0].Hosts = []string{"*.githubusercontent.com"} }},
		{name: "secret for any host", mutate: func(s *Spec) { s.Secrets[0].Hosts = []string{"api.github.com", "*"} }, wantErr: `host "*"`},
		{name: "secret for a top-level domain", mutate: func(s *Spec) { s.Secrets[0].Hosts = []string{"*.com"} }, wantErr: `host "*.com"`},
		{name: "secret for an empty label", mutate: func(s *Spec) { s.Secrets[0].Hosts = []string{"*.github."} }, wantErr: `host "*.github."`},
		{name: "secret for a nested wildcard", mutate: func(s *Spec) { s.Secrets[0].Hosts = []string{"*.*.com"} }, wantErr: `host "*.*.com"`},
		{name: "secret for another wildcard", mutate: func(s *Spec) { s.Secrets[0].Hosts = []string{"api.*.com"} }, wantErr: `host "api.*.com"`},
		{name: "secret for an empty host", mutate: func(s *Spec) { s.Secrets[0].Hosts = []string{""} }, wantErr: `host ""`},
		{name: "placeholder not passed to the Claude API", mutate: func(s *Spec) { s.Secrets[0].Passthrough = nil }, wantErr: `add passthrough = ["api.anthropic.com"]`},
		{name: "placeholder passed to any host", mutate: func(s *Spec) { s.Secrets[0].Passthrough = []string{anthropicHost, "*"} }, wantErr: `host "*"`},
		{name: "Anthropic secret", mutate: func(s *Spec) {
			s.Secrets = append(s.Secrets, Secret{Name: "ANTHROPIC_API_KEY", Hosts: []string{anthropicHost}, HeaderFields: []string{"x-api-key"}})
		}, wantErr: "secret ANTHROPIC_API_KEY"},
		{name: "OAuth token secret", mutate: func(s *Spec) {
			s.Secrets = append(s.Secrets, Secret{Name: "CLAUDE_CODE_OAUTH_TOKEN", Hosts: []string{anthropicHost}, HeaderFields: []string{authHeader}})
		}, wantErr: "secret CLAUDE_CODE_OAUTH_TOKEN"},
		{name: "Anthropic env", mutate: func(s *Spec) { s.EnvNames = append(s.EnvNames, "ANTHROPIC_AUTH_TOKEN") }, wantErr: "env ANTHROPIC_AUTH_TOKEN"},
		{name: "endpoint env", mutate: func(s *Spec) { s.EnvNames = append(s.EnvNames, "ANTHROPIC_BASE_URL") }, wantErr: "env ANTHROPIC_BASE_URL: agent credential and endpoint"},
		{name: "security default", mutate: func(s *Spec) { s.Security = "default" }, wantErr: "want restricted"},
		{name: "user root", mutate: func(s *Spec) { s.User = "root" }, wantErr: "want node"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := validSpec()
			tt.mutate(&spec)

			err := Check(spec)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrPolicy)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestCheck_repoFiles(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../config/sandbox.toml")
	require.NoError(t, err)

	cfg, err := config.Parse(raw)
	require.NoError(t, err)

	require.NoError(t, Check(FromConfig(cfg, raw)))

	// The repo's copy, which the Dockerfile copies there: only its settings, since the Dockerfile sets the modes.
	require.NoError(t, claude.CheckSettings(os.DirFS(filepath.Join("../../config/image", claude.ManagedDir))))
}

func TestFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		dest     string
		wantKind DestKind
	}{
		{dest: "metadata", wantKind: kindGroup},
		{dest: hostGroup, wantKind: kindGroup},
		{dest: "*", wantKind: kindGroup},
		{dest: "link_local", wantKind: kindGroup},
		{dest: "10.0.0.1", wantKind: kindIP},
		{dest: "10.0.0.0/8", wantKind: kindCIDR},
		{dest: ".example.com", wantKind: kindSuffix},
		{dest: "api.example.com", wantKind: kindDomain},
		{dest: "", wantKind: kindUnknown},
	}

	for _, tt := range tests {
		t.Run("destination "+tt.dest, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{Network: config.Network{Deny: []string{tt.dest}}}
			spec := FromConfig(cfg, nil)

			assert.Equal(t, tt.wantKind, spec.Rules[0].DestKind)
			assert.Empty(t, spec.Rules[0].Protocols, "no protocol means any")
		})
	}

	t.Run("maps mounts, secrets and env", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{
			Volumes: []config.Volume{{Name: "ws", Target: "/workspace", Kind: diskKind, Nosuid: true, Nodev: true}},
			Secrets: []config.Secret{{
				Name: patSecret, Allow: []string{"github.com"}, HeaderFields: []string{authHeader}, Placeholder: "PAT",
				Passthrough: []string{anthropicHost},
			}},
			Env: []string{"ANTHROPIC_API_KEY=DUMMY-SECRET-123", "GH_TOKEN=", "NO_VALUE"},
		}
		spec := FromConfig(cfg, nil)

		assert.Equal(t, []Mount{{Type: namedMount, Name: "ws", Target: "/workspace", Kind: diskKind, Nosuid: true, Nodev: true}}, spec.Mounts)
		assert.Equal(t, []Secret{{
			Name: patSecret, Hosts: []string{patHost}, HeaderFields: []string{authHeader}, Placeholder: "PAT",
			Passthrough: []string{anthropicHost},
		}}, spec.Secrets)
		assert.Equal(t, []string{"ANTHROPIC_API_KEY", "GH_TOKEN", "NO_VALUE"}, spec.EnvNames)
		require.ErrorContains(t, Check(spec), "env ANTHROPIC_API_KEY")
	})
}

func TestCheckManaged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		mode    fs.FileMode
		wantErr string
	}{
		{name: "a violation is a policy violation", raw: `{}`, mode: 0o644, wantErr: "forceLoginMethod"},
		{name: "invalid JSON fails closed", raw: `{`, mode: 0o644, wantErr: "managed-settings.json"},
		{name: "a mode violation is a policy violation", raw: `{}`, mode: 0o666, wantErr: "writable by group or others"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckManaged(fstest.MapFS{"managed-settings.json": {Data: []byte(tt.raw), Mode: tt.mode}})
			require.ErrorIs(t, err, ErrPolicy)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestCheckImageEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     []string
		wantErr string
	}{
		{name: "the usual env passes", env: []string{"PATH=/usr/local/bin:/usr/bin", "CLAUDE_CONFIG_DIR=/home/node/claude-state"}},
		{name: "no env passes"},
		{name: "API key", env: []string{"ANTHROPIC_API_KEY=DUMMY-SECRET-123"}, wantErr: "image env ANTHROPIC_API_KEY"},
		{name: "endpoint", env: []string{"ANTHROPIC_BASE_URL=https://proxy"}, wantErr: "image env ANTHROPIC_BASE_URL"},
		{name: "OAuth token", env: []string{"CLAUDE_CODE_OAUTH_TOKEN=DUMMY-SECRET-123"}, wantErr: "image env CLAUDE_CODE_OAUTH_TOKEN"},
		{name: "empty value", env: []string{"ANTHROPIC_AUTH_TOKEN="}, wantErr: "image env ANTHROPIC_AUTH_TOKEN"},
		{name: "name without a value", env: []string{"ANTHROPIC_API_KEY"}, wantErr: "image env ANTHROPIC_API_KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckImageEnv(tt.env)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrPolicy)
			require.ErrorContains(t, err, tt.wantErr)
			assert.NotContains(t, err.Error(), "DUMMY-SECRET-123")
		})
	}
}

// An allow_ips entry from the repo's own spec, through parsing and the check.
func TestCheck_allowIPsEntry(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "sandbox.toml"))
	require.NoError(t, err)

	tests := []struct {
		name         string
		entry        string
		wantParseErr bool
		wantErr      string
	}{
		{name: "a public address passes", entry: "8.8.8.8"},
		{name: "a public range passes", entry: "140.82.112.0/20"},
		{name: "a public IPv6 address passes", entry: "2606:4700:4700::1111"},
		{name: "a private address fails", entry: "10.0.0.1", wantErr: notPublic},
		{name: "every address fails", entry: "0.0.0.0/0", wantErr: notPublic},
		{name: "NAT64 fails", entry: "64:ff9b::/96", wantErr: notPublic},
		{name: "a zoned address fails to parse", entry: "fd00::1%x", wantParseErr: true},
		{name: "a host fails to parse", entry: "example.com", wantParseErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := []byte(strings.Replace(string(raw), "allow_ips = []", `allow_ips = ["`+tt.entry+`"]`, 1))

			cfg, err := config.Parse(body)
			if tt.wantParseErr {
				require.ErrorContains(t, err, "allow_ips")

				return
			}

			require.NoError(t, err)
			require.Equal(t, []string{tt.entry}, cfg.Network.AllowIPs)

			err = Check(FromConfig(cfg, body))
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
