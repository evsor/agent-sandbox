// Filling the values sbx config asks for into the example's sandbox.toml and gitconfig, line by line so the comments survive.

package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SpecValues are the sandbox.toml values sbx config fills in, as typed.
type SpecValues struct {
	Name      string
	CPUs      string
	MemoryMiB string
}

// FillSpec checks the values, sets them on their lines of the example spec and returns the result and its parsed config.
func FillSpec(example []byte, v SpecValues) ([]byte, *Config, error) {
	if !ValidName(v.Name) {
		return nil, nil, fmt.Errorf("sandbox name %q: want lowercase letters, digits and dashes", v.Name)
	}

	cpus, err := strconv.ParseUint(v.CPUs, 10, 8)
	if err != nil || cpus == 0 {
		return nil, nil, fmt.Errorf("cpus %q: want a whole number from 1 to 255", v.CPUs)
	}

	memory, err := strconv.ParseUint(v.MemoryMiB, 10, 32)
	if err != nil || memory == 0 {
		return nil, nil, fmt.Errorf("memory_mib %q: want a whole number from 1 to 4294967295", v.MemoryMiB)
	}

	// The top-level keys come before the first table; name is also a key in the volume and secret tables.
	text := string(example)

	end := strings.Index(text, "\n[")
	if end < 0 {
		end = len(text)
	}

	head := text[:end]

	for _, kv := range [][2]string{{"name", strconv.Quote(v.Name)}, {"cpus", strconv.FormatUint(cpus, 10)}, {"memory_mib", strconv.FormatUint(memory, 10)}} {
		if head, err = setKey(head, kv[0], kv[1]); err != nil {
			return nil, nil, err
		}
	}

	filled := []byte(head + text[end:])

	cfg, err := Parse(filled)
	if err != nil {
		return nil, nil, err
	}

	return filled, cfg, nil
}

// setKey rewrites the one line that sets key, unless it already holds value, which keeps its comment.
func setKey(text, key, value string) (string, error) {
	re := regexp.MustCompile(`(?m)^` + key + ` = (\S+).*$`)

	lines := re.FindAllStringSubmatchIndex(text, -1)
	if len(lines) != 1 {
		return "", fmt.Errorf("the example sandbox.toml has %d top-level %s lines, want 1", len(lines), key)
	}

	m := lines[0]
	if text[m[2]:m[3]] == value {
		return text, nil
	}

	return text[:m[0]] + key + " = " + value + text[m[1]:], nil
}

// gitIdentityLine is the example gitconfig's line that the identity replaces.
const gitIdentityLine = "\t# Add your name and email\n"

// FillGitconfig checks the git name and email and puts the ones that aren't empty under [user] in the example gitconfig.
func FillGitconfig(example []byte, name, email string) ([]byte, error) {
	var lines strings.Builder

	for _, kv := range [][2]string{{"name", name}, {"email", email}} {
		if strings.ContainsAny(kv[1], "\n\r\"\\") || strings.Contains(kv[1], "${") {
			return nil, fmt.Errorf("git %s %q: no newline, \", \\ or ${", kv[0], kv[1])
		}

		if kv[1] != "" {
			fmt.Fprintf(&lines, "\t%s = \"%s\"\n", kv[0], kv[1])
		}
	}

	text := string(example)
	if strings.Count(text, gitIdentityLine) != 1 {
		return nil, fmt.Errorf("the example gitconfig needs one line %q", gitIdentityLine)
	}

	if lines.Len() == 0 {
		return example, nil
	}

	return []byte(strings.Replace(text, gitIdentityLine, lines.String(), 1)), nil
}
