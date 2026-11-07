// guest checks and parses what commands print in the running sandbox.

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// NodeUID is the uid NodeUser must have.
const NodeUID = "1000"

// rootDiskMiB is the root disk size verify requires, whatever the spec says, so a smaller spec fails.
const rootDiskMiB = 16384

// noAnswer is the status curl prints when no HTTP answer arrived.
const noAnswer = "000"

// getentNotFound is getent's exit status when the name doesn't resolve.
const getentNotFound = 2

// blockedExits are curl's exit statuses when the network refuses at once: no such name, connection refused, cut while receiving. A timeout
// isn't among them: it could be an unblocked path where nothing answers.
var blockedExits = []int{6, 7, 56}

// repoName keeps a guest repo's name to one path element that can't be read as an option.
var repoName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// CheckProcStatus checks /proc/self/status: the guest user is uid 1000 and can't gain privileges.
func CheckProcStatus(status string) error {
	fields := map[string]string{}

	for line := range strings.Lines(status) {
		key, value, _ := strings.Cut(line, ":")
		fields[key] = strings.TrimSpace(value)
	}

	// Real, effective, saved and filesystem uid.
	if uids := strings.Fields(fields["Uid"]); len(uids) != 4 || slices.ContainsFunc(uids, func(id string) bool { return id != NodeUID }) {
		return fmt.Errorf("uid is %q", fields["Uid"])
	}

	if fields["NoNewPrivs"] != "1" {
		return fmt.Errorf("NoNewPrivs is %q", fields["NoNewPrivs"])
	}

	return nil
}

// CheckProcMounts checks /proc/mounts: every mount is there, as ext4 with nosuid and nodev.
func CheckProcMounts(table string, mounts []Mount) error {
	return EachMount(mounts, func(m Mount) error {
		mounted := false

		for line := range strings.Lines(table) {
			f := strings.Fields(line)
			if len(f) < 4 || f[1] != m.Target {
				continue
			}

			mounted = true

			opts := strings.Split(f[3], ",")
			if f[2] != "ext4" || !slices.Contains(opts, "nosuid") || !slices.Contains(opts, "nodev") {
				return fmt.Errorf("%s is %q %q", m.Target, f[2], f[3])
			}
		}

		if !mounted {
			return fmt.Errorf("%s is not mounted", m.Target)
		}

		return nil
	})
}

// CheckWritable checks the paths the guest user can write, as listed by find: every mount must be among them.
func CheckWritable(listing string, mounts []Mount) error {
	writable := strings.Fields(listing)

	return EachMount(mounts, func(m Mount) error {
		if !slices.Contains(writable, m.Target) {
			return fmt.Errorf("%s is not writable by node", m.Target)
		}

		return nil
	})
}

// DFArgs are the arguments of the df command that ParseDF reads, for the filesystem at path.
func DFArgs(path string) []string {
	return []string{"--block-size=1", "--output=used,size", path}
}

// ParseDF reads the output of df with DFArgs and returns the bytes used and the filesystem's size, which isn't zero.
func ParseDF(out string) (uint64, uint64, error) {
	f := strings.Fields(out)
	if len(f) != 4 {
		return 0, 0, fmt.Errorf("df printed %q", out)
	}

	used, err1 := strconv.ParseUint(f[2], 10, 64)
	size, err2 := strconv.ParseUint(f[3], 10, 64)

	if err := errors.Join(err1, err2); err != nil || size == 0 {
		return 0, 0, fmt.Errorf("df printed %q", out)
	}

	return used, size, nil
}

// CheckRootDisk checks the output of df with DFArgs on the root filesystem.
func CheckRootDisk(df string) error {
	_, size, err := ParseDF(df)
	if err != nil {
		return err
	}

	want := uint64(rootDiskMiB) << 20

	// The filesystem is a little smaller than its disk.
	if size < want*9/10 || size > want {
		return fmt.Errorf("%d MiB, want about %d MiB", size>>20, rootDiskMiB)
	}

	return nil
}

// CheckSecretsAbsent checks the guest's process environments for each secret's value, which value returns. Its messages name the
// variable, never the value.
func CheckSecretsAbsent(environs []byte, secrets []Secret, value func(string) string) error {
	if len(secrets) == 0 {
		return nil
	}

	if !bytes.Contains(environs, []byte("PATH=")) {
		return errors.New("read no process environment")
	}

	var errs []error

	for _, s := range secrets {
		v := value(s.Name)

		switch {
		case v == "":
			errs = append(errs, fmt.Errorf("%s is not set in sbx's environment, so it can't be compared", s.Name))
		case bytes.Contains(environs, []byte(v)):
			errs = append(errs, fmt.Errorf("the value of %s is in a guest process environment", s.Name))
		}
	}

	return errors.Join(errs...)
}

// ProbeArgs are the arguments of a curl that prints the HTTP status of url, 000 if nothing answered. extra goes before url.
func ProbeArgs(url string, extra ...string) []string {
	args := []string{"-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10"}

	return append(append(args, extra...), url)
}

// CheckAnswered checks the output of a curl with ProbeArgs that exited 0: the host sent an HTTP status.
func CheckAnswered(status string) error {
	if status == "" || status == noAnswer {
		return fmt.Errorf("no HTTP answer: %q", status)
	}

	return nil
}

// CheckBlocked checks a curl with ProbeArgs that should be denied: it exited with a network failure and no HTTP answer.
// Any other failure, such as a missing curl or a bad certificate, doesn't prove the network refused it.
func CheckBlocked(exit int, status string) error {
	if !slices.Contains(blockedExits, exit) || status != noAnswer {
		return fmt.Errorf("curl exited %d with status %q", exit, status)
	}

	return nil
}

// CheckUnresolved checks a getent hosts that should find nothing: exit 2 is getent's "not found".
func CheckUnresolved(exit int, stdout string) error {
	if exit != getentNotFound || stdout != "" {
		return fmt.Errorf("getent exited %d and printed %q", exit, stdout)
	}

	return nil
}

// Placeholder returns the placeholder the guest sees for the secret called name.
func Placeholder(secrets []Secret, name string) (string, error) {
	i := slices.IndexFunc(secrets, func(s Secret) bool { return s.Name == name })
	if i < 0 || secrets[i].Placeholder == "" {
		return "", fmt.Errorf("the live config has no placeholder for %s", name)
	}

	return secrets[i].Placeholder, nil
}

// CheckIsPlaceholder checks a printed variable: it holds the placeholder of the secret called name. Its messages never quote the variable,
// which would be a credential if the check fails.
func CheckIsPlaceholder(printed string, secrets []Secret, name string) error {
	placeholder, err := Placeholder(secrets, name)
	if err != nil {
		return err
	}

	if strings.TrimSpace(printed) != placeholder {
		return fmt.Errorf("the variable is not the placeholder of %s", name)
	}

	return nil
}

// CheckRepoName checks a repo's name, which names a directory on the host or in /workspace.
func CheckRepoName(name string) error {
	if !repoName.MatchString(name) {
		return fmt.Errorf("repo name %q: want letters, digits, dots, dashes and underscores, starting with a letter or digit", name)
	}

	return nil
}

// CheckBranchName checks that a guest branch's name can't be read as an option. git check-ref-format, which only host git can run, does the rest.
func CheckBranchName(name string) error {
	if name == "" || strings.HasPrefix(name, "-") {
		return fmt.Errorf("branch name %q: empty or starts with a dash", name)
	}

	return nil
}

// ParseCommitCount reads the output of git rev-list --count.
func ParseCommitCount(out string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("git rev-list printed %q", out)
	}

	return n, nil
}

// EachMount runs fn on every mount. No mounts at all is a failure: nothing was checked.
func EachMount(mounts []Mount, fn func(Mount) error) error {
	if len(mounts) == 0 {
		return errors.New("the live config names no volumes")
	}

	var errs []error
	for _, m := range mounts {
		errs = append(errs, fn(m))
	}

	return errors.Join(errs...)
}
