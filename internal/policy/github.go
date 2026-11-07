// github checks GitHub repo names and reads them from git remote URLs.

package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// githubRepo is owner/name as GitHub allows it.
var githubRepo = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$`)

// githubPrefixes are the forms of a github.com remote URL that ParseGitHubURL reads.
var githubPrefixes = []string{"git@github.com:", "ssh://git@github.com/", "https://github.com/"}

// CheckGitHubRepo checks that repo is owner/name.
func CheckGitHubRepo(repo string) error {
	if !githubRepo.MatchString(repo) {
		return fmt.Errorf("%q is not owner/name", repo)
	}

	return nil
}

// ParseGitHubURL returns the owner/name of a github.com remote URL. Its error doesn't repeat the URL, which may hold a credential.
func ParseGitHubURL(url string) (string, error) {
	for _, prefix := range githubPrefixes {
		rest, ok := strings.CutPrefix(url, prefix)
		if !ok {
			continue
		}

		repo := strings.TrimSuffix(rest, ".git")
		if githubRepo.MatchString(repo) {
			return repo, nil
		}
	}

	return "", errors.New("not a github.com URL like git@github.com:owner/name, ssh://git@github.com/owner/name or https://github.com/owner/name")
}
