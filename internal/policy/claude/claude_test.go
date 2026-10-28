// Tests for Claude Code's rules: one case per managed-settings rule, in the base file and in drop-ins, and per mode rule, each with a
// passing and a failing case.
//
// They run with make test, so in CI on every PR; a failing case fails the build.

package claude

import (
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckSettings(t *testing.T) {
	t.Parallel()

	const (
		off   = "disable"
		login = "forceLoginMethod"
		drop  = "managed-settings.d/50-team.json"
	)

	valid := func() map[string]any {
		return map[string]any{
			login:                             "claudeai",
			"allowManagedPermissionRulesOnly": true,
			"allowManagedHooksOnly":           true,
			"allowManagedMcpServersOnly":      true,
			"env":                             map[string]any{"DISABLE_TELEMETRY": "1"},
			"permissions":                     map[string]any{"disableBypassPermissionsMode": off, "disableAutoMode": off},
		}
	}

	file := func(body string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(body)} }
	link := &fstest.MapFile{Data: []byte("/home/node/claude-state/x.json"), Mode: fs.ModeSymlink}

	tests := []struct {
		name    string
		mutate  func(s map[string]any) // the base settings
		files   fstest.MapFS           // added beside them
		wantErr string
	}{
		{name: "valid settings pass"},
		{name: "no forced login", mutate: func(s map[string]any) { delete(s, login) }, wantErr: login},
		{name: "console login", mutate: func(s map[string]any) { s[login] = "console" }, wantErr: login},
		{name: "bypass allowed", mutate: func(s map[string]any) {
			s["permissions"] = map[string]any{"disableAutoMode": off}
		}, wantErr: "bypass and auto mode"},
		{name: "auto mode allowed", mutate: func(s map[string]any) {
			s["permissions"] = map[string]any{"disableBypassPermissionsMode": off}
		}, wantErr: "bypass and auto mode"},
		{name: "managed-only hooks off", mutate: func(s map[string]any) { s["allowManagedHooksOnly"] = false }, wantErr: "allowManagedHooksOnly must be true"},
		{name: "managed-only rules off", mutate: func(s map[string]any) { delete(s, "allowManagedPermissionRulesOnly") }, wantErr: "allowManagedPermissionRulesOnly must be true"},
		{name: "managed-only MCP off", mutate: func(s map[string]any) { delete(s, "allowManagedMcpServersOnly") }, wantErr: "allowManagedMcpServersOnly must be true"},
		{name: "flag as a string", mutate: func(s map[string]any) { s["allowManagedHooksOnly"] = "true" }, wantErr: "allowManagedHooksOnly must be true"},
		{name: "login only under another case", mutate: func(s map[string]any) {
			delete(s, login)
			s["ForceLoginMethod"] = "claudeai"
		}, wantErr: login},
		{name: "bypass off only under another case", mutate: func(s map[string]any) {
			s["permissions"] = map[string]any{"DisableBypassPermissionsMode": off, "disableAutoMode": off}
		}, wantErr: "bypass and auto mode"},
		{name: "apiKeyHelper", mutate: func(s map[string]any) { s["apiKeyHelper"] = "/bin/key" }, wantErr: "apiKeyHelper"},
		{name: "policyHelper", mutate: func(s map[string]any) { s["policyHelper"] = map[string]any{"path": "/bin/policy"} }, wantErr: "policyHelper"},
		{name: "API key in env", mutate: func(s map[string]any) {
			s["env"] = map[string]any{"ANTHROPIC_API_KEY": "x"}
		}, wantErr: "env ANTHROPIC_API_KEY"},
		{name: "endpoint in env", mutate: func(s map[string]any) {
			s["env"] = map[string]any{"ANTHROPIC_BASE_URL": "https://proxy"}
		}, wantErr: "env ANTHROPIC_BASE_URL"},
		{name: "OAuth token in env", mutate: func(s map[string]any) {
			s["env"] = map[string]any{"CLAUDE_CODE_OAUTH_TOKEN": "x"}
		}, wantErr: "env CLAUDE_CODE_OAUTH_TOKEN"},
		{name: "a linked settings file", files: fstest.MapFS{settingsFile: link}, wantErr: "must be a regular file"},
		{name: "a drop-in adds rules and env", files: fstest.MapFS{
			drop: file(`{"permissions": {"allow": ["Bash(go *)"]}, "env": {"GOFLAGS": "-mod=mod"}}`),
		}},
		{name: "a drop-in restates the baseline", files: fstest.MapFS{drop: file(`{"forceLoginMethod": "claudeai", "allowManagedHooksOnly": true}`)}},
		{name: "hidden and non-JSON drop-ins are ignored", files: fstest.MapFS{
			"managed-settings.d/.50-team.json": file("{"), "managed-settings.d/README.md": file("{"),
		}},
		{name: "a drop-in changes the login", files: fstest.MapFS{drop: file(`{"forceLoginMethod": "console"}`)}, wantErr: "50-team.json: forceLoginMethod"},
		{name: "a drop-in allows bypass", files: fstest.MapFS{
			drop: file(`{"permissions": {"disableBypassPermissionsMode": null}}`),
		}, wantErr: "50-team.json: bypass and auto mode"},
		{name: "a drop-in turns managed-only hooks off", files: fstest.MapFS{
			drop: file(`{"allowManagedHooksOnly": false}`),
		}, wantErr: "50-team.json: allowManagedHooksOnly must be true"},
		{name: "a drop-in sets apiKeyHelper", files: fstest.MapFS{drop: file(`{"apiKeyHelper": "/bin/key"}`)}, wantErr: "50-team.json: apiKeyHelper"},
		{name: "a drop-in sets an API key", files: fstest.MapFS{
			drop: file(`{"env": {"ANTHROPIC_API_KEY": "x"}}`),
		}, wantErr: "50-team.json: env ANTHROPIC_API_KEY"},
		{name: "a drop-in nulls permissions", files: fstest.MapFS{drop: file(`{"permissions": null}`)}, wantErr: "must be objects"},
		{name: "an invalid drop-in fails closed", files: fstest.MapFS{drop: file("{")}, wantErr: "50-team.json"},
		{name: "a linked drop-in", files: fstest.MapFS{drop: link}, wantErr: "must be a regular file"},
		{name: "a linked drop-in directory", files: fstest.MapFS{dropInDir: link}, wantErr: "must be a directory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := valid()
			if tt.mutate != nil {
				tt.mutate(s)
			}

			raw, err := json.Marshal(s)
			require.NoError(t, err)

			fsys := fstest.MapFS{settingsFile: {Data: raw}}
			maps.Copy(fsys, tt.files)

			err = CheckSettings(fsys)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			assert.ErrorContains(t, err, tt.wantErr)
		})
	}

	t.Run("invalid JSON fails closed", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, CheckSettings(fstest.MapFS{settingsFile: {Data: []byte("{")}}), settingsFile)
	})

	t.Run("a missing settings file fails closed", func(t *testing.T) {
		t.Parallel()

		require.ErrorContains(t, CheckSettings(fstest.MapFS{}), settingsFile)
	})
}

func TestCheckModes(t *testing.T) {
	t.Parallel()

	const skill = "skills/review/SKILL.md"

	file := func(mode fs.FileMode) *fstest.MapFile { return &fstest.MapFile{Data: []byte("{}"), Mode: mode} }
	dir := func(mode fs.FileMode) *fstest.MapFile { return &fstest.MapFile{Mode: fs.ModeDir | mode} }

	tests := []struct {
		name    string
		fsys    fs.FS
		wantErr string
	}{
		{name: "read-only for others passes", fsys: fstest.MapFS{
			settingsFile: file(0o644), "skills": dir(0o755), skill: file(0o644), "CLAUDE.md": file(0o640),
		}},
		{name: "a group-writable file", fsys: fstest.MapFS{settingsFile: file(0o664)}, wantErr: settingsFile + ": must not be writable"},
		{name: "an other-writable file", fsys: fstest.MapFS{"CLAUDE.md": file(0o646)}, wantErr: "CLAUDE.md: must not be writable"},
		{name: "a writable directory", fsys: fstest.MapFS{
			"skills": dir(0o777), skill: file(0o644),
		}, wantErr: "skills: must not be writable"},
		{name: "a writable file deep down", fsys: fstest.MapFS{skill: file(0o666)}, wantErr: skill},
		{name: "a link anywhere", fsys: fstest.MapFS{
			"skills/review": {Data: []byte("/home/node/claude-state/skill"), Mode: fs.ModeSymlink | 0o777},
		}, wantErr: "skills/review: must not be a link"},
		{name: "a missing directory fails closed", fsys: os.DirFS(filepath.Join(t.TempDir(), "missing")), wantErr: "no such file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckModes(tt.fsys)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
