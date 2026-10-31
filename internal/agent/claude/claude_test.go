package claude

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLogin(t *testing.T) {
	t.Parallel()

	const errLogin = "parsing claude auth status"

	tests := []struct {
		name    string
		out     string
		want    Login
		wantErr string
	}{
		{
			name: "logged in",
			out:  `{"loggedIn": true, "authMethod": "claude.ai", "apiProvider": "firstParty"}`,
			want: Login{LoggedIn: true, Method: "claude.ai"},
		},
		{
			name: "not logged in",
			out:  `{"loggedIn": false, "authMethod": "none"}`,
			want: Login{Method: "none"},
		},
		{name: "empty output", out: "", wantErr: errLogin},
		{name: "not json", out: "Not logged in", wantErr: errLogin},
		{name: "wrong shape", out: `[]`, wantErr: errLogin},
		{name: "wrong field type", out: `{"loggedIn": "yes"}`, wantErr: errLogin},
		{name: "no loggedIn field", out: `{"authMethod": "none"}`, wantErr: "no loggedIn field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseLogin([]byte(tt.out))

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseSessions(t *testing.T) {
	t.Parallel()

	const errSessions = "parsing claude agents"

	background := Session{ID: "151b5082", Kind: "background", Name: "fix it", Cwd: "/workspace/repo", State: "working"}

	tests := []struct {
		name    string
		out     string
		want    []Session
		wantErr string
	}{
		{name: "none", out: `[]`, want: []Session{}},
		{
			name: "background session",
			out: `[{"pid": 42, "id": "151b5082", "cwd": "/workspace/repo", "kind": "background", "startedAt": 1,
				"sessionId": "u", "name": "fix it", "status": "busy", "state": "working"}]`,
			want: []Session{background},
		},
		{
			name: "interactive session left out",
			out: `[{"pid": 7, "cwd": "/workspace/repo", "kind": "interactive", "startedAt": 1, "status": "idle"},
				{"id": "151b5082", "cwd": "/workspace/repo", "kind": "background", "name": "fix it", "state": "working"}]`,
			want: []Session{background},
		},
		{name: "empty output", out: "", wantErr: errSessions},
		{name: "not json", out: "Workspace not trusted", wantErr: errSessions},
		{name: "wrong shape", out: `{"id": "151b5082"}`, wantErr: errSessions},
		{name: "wrong field type", out: `[{"id": 1}]`, wantErr: errSessions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSessions([]byte(tt.out))

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
