// Tests for reading a live config: FromConfigJSON on testdata/live.json, a recorded live config holding only dummy values, building the
// Spec that FromConfig builds from the repo's sandbox.toml, and failing closed on what it can't read; liveDestination normalizing each
// stored destination the way classify does a sandbox.toml one.
//
// They run with make test, so in CI on every PR; a failing case fails the build.

package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/evsor/agent-sandbox/internal/config"
)

func TestFromConfigJSON(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "live.json"))
	require.NoError(t, err)

	disk := func(string) (string, error) { return diskKind, nil }

	spec, err := FromConfigJSON(raw, disk)
	require.NoError(t, err)

	t.Run("parses the stored config", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "test-sbx-msb:4706ca6", spec.Image)
		assert.Equal(t, "node", spec.User)
		assert.Equal(t, "restricted", spec.Security)
		assert.Equal(t, Mount{Type: namedMount, Name: "test-sbx-state", Target: "/home/node/claude-state", Kind: diskKind, Nosuid: true, Nodev: true}, spec.Mounts[1])
		assert.Equal(t, Rule{Action: actionDeny, Direction: egress, DestKind: kindGroup, Dest: "link-local"}, spec.Rules[2])
		assert.Equal(t, allow(kindDomain, "api.anthropic.com"), spec.Rules[5])
		assert.Equal(t, []Secret{{
			Name: "TEST_SBX_SECRET", Hosts: []string{"httpbin.org"},
			HeaderFields: []string{authHeader}, Placeholder: "TESTSBXPLACEHOLDER",
		}}, spec.Secrets)
	})

	t.Run("leaves secret values out of the scanned strings", func(t *testing.T) {
		t.Parallel()

		assert.NotContains(t, spec.Strings, "DUMMY-SECRET-123")
		assert.Contains(t, spec.Strings, "TESTSBXPLACEHOLDER")
	})

	t.Run("passes the check", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, Check(spec))
	})

	t.Run("builds the spec FromConfig builds from the repo's sandbox.toml", func(t *testing.T) {
		t.Parallel()

		toml, err := os.ReadFile("../../config/sandbox.toml")
		require.NoError(t, err)

		cfg, err := config.Parse(toml)
		require.NoError(t, err)

		want := FromConfig(cfg, toml)

		assert.Equal(t, want.Rules, spec.Rules)
		assert.Equal(t,
			[]any{want.User, want.Security, want.DefaultEgress, want.DefaultIngress, want.Strict, want.InterceptTLS},
			[]any{spec.User, spec.Security, spec.DefaultEgress, spec.DefaultIngress, spec.Strict, spec.InterceptTLS})

		// The recording's volumes have test-* names; everything else about the mounts must match.
		require.Len(t, spec.Mounts, len(want.Mounts))

		for i := range want.Mounts {
			want.Mounts[i].Name = spec.Mounts[i].Name
		}

		assert.Equal(t, want.Mounts, spec.Mounts)
	})

	t.Run("without volume kinds the mounts fail closed", func(t *testing.T) {
		t.Parallel()

		unknown, err := FromConfigJSON(raw, nil)
		require.NoError(t, err)

		assert.Empty(t, unknown.Mounts[0].Kind)
		require.ErrorContains(t, Check(unknown), "want a named disk volume")
	})

	t.Run("a failed kind lookup is an error", func(t *testing.T) {
		t.Parallel()

		_, err := FromConfigJSON(raw, func(string) (string, error) { return "", errors.New("no such volume") })
		require.ErrorContains(t, err, "volume test-sbx-workspace: no such volume")
	})

	t.Run("invalid JSON is an error", func(t *testing.T) {
		t.Parallel()

		_, err := FromConfigJSON([]byte("{"), disk)
		require.ErrorContains(t, err, "parsing the live config")
	})

	t.Run("a field of the wrong type is an error", func(t *testing.T) {
		t.Parallel()

		_, err := FromConfigJSON([]byte(`{"network": {"strict": "yes"}}`), disk)
		require.ErrorContains(t, err, "reading the live config")
	})

	t.Run("a secret host of another shape is an error", func(t *testing.T) {
		t.Parallel()

		_, err := FromConfigJSON([]byte(`{"network": {"secrets": {"secrets": [{
			"env_var": "GITHUB_PAT", "allowed_hosts": [{"exact": "github.com"}, {"regex": ".*"}]
		}]}}}`), disk)
		require.ErrorContains(t, err, "secret GITHUB_PAT: an allowed host of an unknown shape")
	})

	t.Run("a secret host stored as a bare string is an error", func(t *testing.T) {
		t.Parallel()

		_, err := FromConfigJSON([]byte(`{"network": {"secrets": {"secrets": [{"env_var": "GITHUB_PAT", "allowed_hosts": ["any"]}]}}}`), disk)
		require.ErrorContains(t, err, "reading the live config")
	})

	t.Run("scans keys too", func(t *testing.T) {
		t.Parallel()

		labeled, err := FromConfigJSON([]byte(`{"labels": {"${HOME}": "x"}}`), disk)
		require.NoError(t, err)

		require.ErrorContains(t, Check(labeled), `"${"`)
	})
}

func TestLiveDestination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw      string
		wantKind DestKind
		wantDest string
	}{
		{raw: `"any"`, wantKind: kindGroup, wantDest: "*"},
		{raw: `"other"`, wantKind: kindUnknown, wantDest: "other"},
		{raw: `{"group":"link_local"}`, wantKind: kindGroup, wantDest: "link-local"},
		{raw: `{"group":"host"}`, wantKind: kindGroup, wantDest: hostGroup},
		{raw: `{"group":"intranet"}`, wantKind: kindUnknown, wantDest: "intranet"},
		{raw: `{"domain":"a.b"}`, wantKind: kindDomain, wantDest: "a.b"},
		{raw: `{"domain":""}`, wantKind: kindUnknown, wantDest: "domain"},
		{raw: `{"domain_suffix":"b.c"}`, wantKind: kindSuffix, wantDest: ".b.c"},
		{raw: `{"cidr":"10.0.0.0/8"}`, wantKind: kindCIDR, wantDest: "10.0.0.0/8"},
		{raw: `{"other":"x"}`, wantKind: kindUnknown, wantDest: "other"},
		{raw: `{"a":"1","b":"2"}`, wantKind: kindUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			t.Parallel()

			kind, dest := liveDestination(json.RawMessage(tt.raw))
			assert.Equal(t, tt.wantKind, kind)

			if tt.wantDest != "" {
				assert.Equal(t, tt.wantDest, dest)
			}
		})
	}
}
