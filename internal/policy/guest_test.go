// Tests for checking what guest commands print: one case per way each check can pass or fail, on output in the shape the guest prints it.

package policy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var guestMounts = []Mount{{Target: "/vol/work"}, {Target: "/vol/state"}}

func TestCheckProcStatus(t *testing.T) {
	t.Parallel()

	const errUID = "uid is"

	tests := []struct {
		name    string
		status  string
		wantErr string
	}{
		{name: "node, no new privileges", status: "Name:\tcat\nUid:\t1000\t1000\t1000\t1000\nNoNewPrivs:\t1\n"},
		{name: "root", status: "Uid:\t0\t0\t0\t0\nNoNewPrivs:\t1\n", wantErr: errUID},
		{name: "one uid differs", status: "Uid:\t1000\t0\t1000\t1000\nNoNewPrivs:\t1\n", wantErr: errUID},
		{name: "too few uids", status: "Uid:\t1000\nNoNewPrivs:\t1\n", wantErr: errUID},
		{name: "new privileges allowed", status: "Uid:\t1000\t1000\t1000\t1000\nNoNewPrivs:\t0\n", wantErr: "NoNewPrivs is"},
		{name: "empty", status: "", wantErr: errUID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckProcStatus(tt.status)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestCheckProcMounts(t *testing.T) {
	t.Parallel()

	const (
		workspace = "/dev/vdb /vol/work ext4 rw,nosuid,nodev,relatime 0 0\n"
		state     = "/dev/vdc /vol/state ext4 rw,nosuid,nodev 0 0\n"
	)

	tests := []struct {
		name    string
		table   string
		mounts  []Mount
		wantErr string
	}{
		{name: "both as required", table: "proc /proc proc rw 0 0\n" + workspace + state, mounts: guestMounts},
		{name: "one missing", table: workspace, mounts: guestMounts, wantErr: "/vol/state is not mounted"},
		{name: "wrong filesystem", table: "/dev/vdb /vol/work xfs rw,nosuid,nodev 0 0\n" + state, mounts: guestMounts, wantErr: `/vol/work is "xfs"`},
		{name: "no nosuid", table: "/dev/vdb /vol/work ext4 rw,nodev 0 0\n" + state, mounts: guestMounts, wantErr: "/vol/work is"},
		{name: "no nodev", table: "/dev/vdb /vol/work ext4 rw,nosuid 0 0\n" + state, mounts: guestMounts, wantErr: "/vol/work is"},
		{name: "a bad mount over a good one", table: workspace + "/dev/vdd /vol/work ext4 rw 0 0\n" + state, mounts: guestMounts, wantErr: "/vol/work is"},
		{name: "no mounts in the config", table: workspace, wantErr: "names no volumes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckProcMounts(tt.table, tt.mounts)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestCheckWritable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		listing string
		mounts  []Mount
		wantErr string
	}{
		{name: "both listed", listing: "/vol/work\n/vol/state\n", mounts: guestMounts},
		{name: "one missing", listing: "/vol/work\n", mounts: guestMounts, wantErr: "/vol/state is not writable"},
		{name: "no mounts in the config", listing: "/vol/work\n", wantErr: "names no volumes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckWritable(tt.listing, tt.mounts)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestParseDF(t *testing.T) {
	t.Parallel()

	const errDF = "df printed"

	tests := []struct {
		name     string
		out      string
		wantUsed uint64
		wantSize uint64
		wantErr  string
	}{
		{name: "used and size", out: "Used 1B-blocks\n1024 4096\n", wantUsed: 1024, wantSize: 4096},
		{name: "nothing printed, as when df fails", out: "", wantErr: errDF},
		{name: "the wrong columns", out: "1B-blocks\n4096\n", wantErr: errDF},
		{name: "not a number", out: "Used 1B-blocks\nmany 4096\n", wantErr: errDF},
		{name: "a size of zero", out: "Used 1B-blocks\n0 0\n", wantErr: errDF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			used, size, err := ParseDF(tt.out)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantUsed, used)
			assert.Equal(t, tt.wantSize, size)
		})
	}
}

func TestCheckRootDisk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		df      string
		wantErr string
	}{
		{name: "exactly the disk", df: "Used 1B-blocks\n1 17179869184\n"},
		{name: "a little smaller", df: "Used 1B-blocks\n1 16000000000\n"},
		{name: "too small", df: "Used 1B-blocks\n1 10737418240\n", wantErr: "10240 MiB, want about 16384 MiB"},
		{name: "too big", df: "Used 1B-blocks\n1 17179869185\n", wantErr: "want about 16384 MiB"},
		{name: "unreadable", df: "", wantErr: "df printed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckRootDisk(tt.df)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestEachMount(t *testing.T) {
	t.Parallel()

	require.ErrorContains(t, EachMount(nil, func(Mount) error { return nil }), "names no volumes")

	errBad := errors.New("bad")

	var seen []string

	err := EachMount(guestMounts, func(m Mount) error {
		seen = append(seen, m.Target)

		return errBad
	})

	require.ErrorIs(t, err, errBad)
	assert.Equal(t, []string{"/vol/work", "/vol/state"}, seen, "a failure doesn't stop the rest")
}
