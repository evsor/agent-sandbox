// guest judges and parses what commands print in the running sandbox.

package policy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// NodeUID is the uid NodeUser must have.
const NodeUID = "1000"

// rootDiskMiB is the root disk size verify requires, whatever the spec says, so a smaller spec fails.
const rootDiskMiB = 16384

// CheckProcStatus judges /proc/self/status: the guest user is uid 1000 and can't gain privileges.
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

// CheckProcMounts judges /proc/mounts: every mount is there, as ext4 with nosuid and nodev.
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

// CheckWritable judges the paths the guest user can write, as listed by find: every mount must be among them.
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

// CheckRootDisk judges the output of df with DFArgs on the root filesystem.
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
