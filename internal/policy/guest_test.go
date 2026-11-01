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

func TestCheckSecretsAbsent(t *testing.T) {
	t.Parallel()

	const (
		environs = "PATH=/usr/bin\x00GH_TOKEN=placeholder\x00"
		value    = "DUMMY-SECRET-123"
	)

	secrets := []Secret{{Name: "ONE"}, {Name: "TWO"}}
	values := map[string]string{"ONE": "DUMMY-SECRET-456", "TWO": value}

	tests := []struct {
		name     string
		environs string
		secrets  []Secret
		values   map[string]string
		wantErr  string
	}{
		{name: "no value in the guest", environs: environs, secrets: secrets, values: values},
		{name: "no secrets, nothing read", environs: ""},
		{name: "a value in the guest", environs: environs + "LEAK=" + value + "\x00", secrets: secrets, values: values, wantErr: "the value of TWO is in"},
		{name: "nothing read", environs: "", secrets: secrets, values: values, wantErr: "read no process environment"},
		{name: "a variable unset on the host", environs: environs, secrets: secrets, values: map[string]string{"ONE": "x"}, wantErr: "TWO is not set"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckSecretsAbsent([]byte(tt.environs), tt.secrets, func(name string) string { return tt.values[name] })
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.NotContains(t, err.Error(), value)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestProbeArgs(t *testing.T) {
	t.Parallel()

	args := ProbeArgs("https://x/", "-H", "Host: y")
	assert.Equal(t, []string{"-H", "Host: y", "https://x/"}, args[len(args)-3:])
	assert.Contains(t, args, "%{http_code}")
}

func TestCheckAnswered(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  string
		wantErr bool
	}{
		{name: "a success", status: "200"},
		{name: "any HTTP status is an answer", status: "404"},
		{name: "no answer", status: "000", wantErr: true},
		{name: "empty", status: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckAnswered(tt.status)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestCheckBlocked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		exit    int
		status  string
		wantErr bool
	}{
		{name: "no such name", exit: 6, status: "000"},
		{name: "connection refused", exit: 7, status: "000"},
		{name: "cut while receiving", exit: 56, status: "000"},
		{name: "the host answered", exit: 0, status: "200", wantErr: true},
		{name: "a failure after an answer", exit: 56, status: "200", wantErr: true},
		{name: "a timeout", exit: 28, status: "000", wantErr: true},
		{name: "curl is missing", exit: 127, status: "", wantErr: true},
		{name: "a bad certificate", exit: 60, status: "000", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckBlocked(tt.exit, tt.status)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestCheckUnresolved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		exit    int
		stdout  string
		wantErr bool
	}{
		{name: "not found", exit: 2},
		{name: "resolved", exit: 0, stdout: "1.2.3.4 x\n", wantErr: true},
		{name: "getent is missing", exit: 127, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckUnresolved(tt.exit, tt.stdout)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestPlaceholder(t *testing.T) {
	t.Parallel()

	secrets := []Secret{{Name: "A"}, {Name: "B", Placeholder: "PH"}}

	got, err := Placeholder(secrets, "B")
	require.NoError(t, err)
	assert.Equal(t, "PH", got)

	_, err = Placeholder(secrets, "A")
	require.Error(t, err, "no placeholder")

	_, err = Placeholder(secrets, "C")
	require.Error(t, err, "no such secret")
}

func TestCheckIsPlaceholder(t *testing.T) {
	t.Parallel()

	secrets := []Secret{{Name: "S", Placeholder: "PH"}}

	tests := []struct {
		name    string
		printed string
		secret  string
		wantErr bool
	}{
		{name: "the placeholder", printed: "PH\n", secret: "S"},
		{name: "another value", printed: "DUMMY-SECRET-123\n", secret: "S", wantErr: true},
		{name: "no such secret", printed: "PH\n", secret: "T", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckIsPlaceholder(tt.printed, secrets, tt.secret)
			if tt.wantErr {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "DUMMY", "errors never carry the variable")

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
