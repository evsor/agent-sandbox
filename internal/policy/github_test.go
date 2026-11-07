// Tests for GitHub repo names: one case per form each function accepts or refuses.

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const ownerName = "evsor/agent-sandbox"

func TestCheckGitHubRepo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		repo    string
		wantErr bool
	}{
		{name: "plain", repo: ownerName},
		{name: "dots and underscores in the name", repo: "o/my_repo.v2"},
		{name: "nothing", repo: "", wantErr: true},
		{name: "no owner", repo: "agent-sandbox", wantErr: true},
		{name: "empty owner", repo: "/name", wantErr: true},
		{name: "empty name", repo: "owner/", wantErr: true},
		{name: "owner starts with a dash", repo: "-x/y", wantErr: true},
		{name: "dot in the owner", repo: "o.o/n", wantErr: true},
		{name: "three parts", repo: "a/b/c", wantErr: true},
		{name: "space", repo: "a/b c", wantErr: true},
		{name: "trailing newline", repo: "a/b\n", wantErr: true},
		{name: "URL", repo: "https://github.com/a/b", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckGitHubRepo(tt.repo)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestParseGitHubURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{name: "scp-like", url: "git@github.com:evsor/agent-sandbox.git", want: ownerName},
		{name: "scp-like without .git", url: "git@github.com:evsor/agent-sandbox", want: ownerName},
		{name: "ssh", url: "ssh://git@github.com/evsor/agent-sandbox.git", want: ownerName},
		{name: "ssh without .git", url: "ssh://git@github.com/evsor/agent-sandbox", want: ownerName},
		{name: "https", url: "https://github.com/evsor/agent-sandbox.git", want: ownerName},
		{name: "https without .git", url: "https://github.com/evsor/agent-sandbox", want: ownerName},
		{name: "nothing", url: "", wantErr: true},
		{name: "another host", url: "https://gitlab.com/evsor/agent-sandbox.git", wantErr: true},
		{name: "a host that starts like GitHub's", url: "https://github.com.evil.example/o/n.git", wantErr: true},
		{name: "credential in the URL", url: "https://user:DUMMY-SECRET-123@github.com/o/n.git", wantErr: true}, //nolint:gosec // a dummy, to check the error doesn't repeat it
		{name: "http", url: "http://github.com/o/n.git", wantErr: true},
		{name: "ssh with a port", url: "ssh://git@github.com:22/o/n.git", wantErr: true},
		{name: "trailing slash", url: "https://github.com/o/n/", wantErr: true},
		{name: "extra path", url: "https://github.com/o/n/tree/main", wantErr: true},
		{name: "no name", url: "git@github.com:o", wantErr: true},
		{name: "only .git", url: "https://github.com/o/.git", wantErr: true},
		{name: "local path", url: "/srv/git/o/n.git", wantErr: true},
		{name: "owner starts with a dash", url: "git@github.com:-o/n.git", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseGitHubURL(tt.url)
			if tt.wantErr {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "DUMMY-SECRET-123")

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
