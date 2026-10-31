// Package claude defines policy rules specific to Claude Code: the checks on its managed settings, and the judgement of what its commands
// print in the running sandbox for sbx verify.
package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	agent "github.com/evsor/agent-sandbox/internal/agent/claude"
)

// StateTarget is where the state volume mounts. The image sets CLAUDE_CONFIG_DIR to it.
const StateTarget = "/home/node/claude-state"

// ManagedDir is the managed directory in the image.
const ManagedDir = "/etc/claude-code"

// settingsFile is the main settings file in ManagedDir.
// dropInDir is the directory for additional settings in ManagedDir.
const (
	settingsFile = "managed-settings.json"
	dropInDir    = "managed-settings.d"
)

// loginMethod is the only login allowed: the subscription.
const loginMethod = "claudeai"

var managedOnly = []string{"allowManagedPermissionRulesOnly", "allowManagedHooksOnly", "allowManagedMcpServersOnly"}

// loadFailures are what Claude Code prints when a whole managed source isn't in effect. Invalid entries leave the rest enforced and aren't judged.
var loadFailures = []string{"Managed settings failed to load", "none of its settings are in effect"}

var forbiddenKeys = []string{"apiKeyHelper", "policyHelper"}

// IsAgentAuthVar reports whether the environment variable is an agent authentication variable for Claude. Claude should log in with subscription only.
func IsAgentAuthVar(name string) bool {
	return strings.HasPrefix(name, "ANTHROPIC_") || name == "CLAUDE_CODE_OAUTH_TOKEN"
}

// CheckSettings checks the settings files in the managed directory.
func CheckSettings(fsys fs.FS) error {
	errs := []error{checkFile(fsys, settingsFile, true)}

	names, err := additionalSettings(fsys)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}

	for _, name := range names {
		errs = append(errs, checkFile(fsys, name, false))
	}

	return errors.Join(errs...)
}

// Get files in managed-settings.d ending in .json, hidden ones aside.
func additionalSettings(fsys fs.FS) ([]string, error) {
	info, err := fs.Lstat(fsys, dropInDir)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("%s: %w", dropInDir, err)
	case !info.IsDir():
		return nil, fmt.Errorf("%s: must be a directory, not a link or a file", dropInDir)
	}

	entries, err := fs.ReadDir(fsys, dropInDir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dropInDir, err)
	}

	var names []string

	for _, e := range entries {
		if strings.EqualFold(path.Ext(e.Name()), ".json") && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, path.Join(dropInDir, e.Name()))
		}
	}

	return names, nil
}

// Check one settings file.
func checkFile(fsys fs.FS, name string, base bool) error {
	info, err := fs.Lstat(fsys, name)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: must be a regular file", name)
	}

	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	return checkSettings(name, top, base)
}

// Checks the decoded settings file name for policy violations.
func checkSettings(name string, top map[string]json.RawMessage, base bool) error {
	var errs []error

	fail := func(msg string) { errs = append(errs, fmt.Errorf("%s: %s", name, msg)) }

	perms, permsOK := object(top, "permissions")
	env, envOK := object(top, "env")

	if !permsOK || !envOK {
		fail("permissions and env must be objects")
	}

	if !holds(top, "forceLoginMethod", loginMethod, base) {
		fail(`forceLoginMethod must be "claudeai"`)
	}

	if !holds(perms, "disableBypassPermissionsMode", "disable", base) || !holds(perms, "disableAutoMode", "disable", base) {
		fail("bypass and auto mode must be disabled")
	}

	for _, key := range managedOnly {
		if !holds(top, key, true, base) {
			fail(key + " must be true")
		}
	}

	for _, key := range forbiddenKeys {
		if _, ok := top[key]; ok {
			fail(key + " is not allowed")
		}
	}

	for envName := range env {
		if IsAgentAuthVar(envName) {
			fail("env " + envName + " is not allowed")
		}
	}

	return errors.Join(errs...)
}

// holds reports whether obj[key] decodes to want; a missing key holds unless required.
func holds[T comparable](obj map[string]json.RawMessage, key string, want T, required bool) bool {
	raw, ok := obj[key]
	if !ok {
		return !required
	}

	var v T

	return json.Unmarshal(raw, &v) == nil && v == want
}

// Decode as a JSON object.
func object(obj map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool) {
	raw, ok := obj[key]
	if !ok {
		return nil, true
	}

	var v map[string]json.RawMessage

	return v, json.Unmarshal(raw, &v) == nil && v != nil
}

// CheckModes checks entries in the managed directory: no links, nothing writable by group or others, and everything readable by others,
// since Claude Code silently skips a managed file its user can't read.
func CheckModes(fsys fs.FS) error {
	var errs []error

	walkErr := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		readable := fs.FileMode(0o004)
		if d.IsDir() {
			readable = 0o005
		}

		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			errs = append(errs, fmt.Errorf("%s: must not be a link", name))
		case info.Mode().Perm()&0o022 != 0:
			errs = append(errs, fmt.Errorf("%s: must not be writable by group or others", name))
		case info.Mode().Perm()&readable != readable:
			errs = append(errs, fmt.Errorf("%s: must be readable by others", name))
		}

		return nil
	})

	return errors.Join(append(errs, walkErr)...)
}

// CheckManagedListing judges the entries under ManagedDir that root doesn't own, or node can write or can't read, as listed in the guest:
// there must be none.
func CheckManagedListing(listing string) error {
	if entries := strings.TrimSpace(listing); entries != "" {
		return fmt.Errorf("root must own these, and node must be able to read but not write them: %q", entries)
	}

	return nil
}

// CheckManagedLoad judges the output of `claude auth status --json`, which needs no login or model call. It reports the forced login
// method from any settings source, so node's own settings can satisfy this; CheckManagedListing covers managed files node can't read.
func CheckManagedLoad(stdout, stderr []byte) error {
	for _, failure := range loadFailures {
		if bytes.Contains(stderr, []byte(failure)) {
			return fmt.Errorf("claude reports: %q", bytes.TrimSpace(stderr))
		}
	}

	login, err := agent.ParseLogin(stdout)
	if err != nil {
		return err
	}

	if login.ForcedMethod != loginMethod {
		return fmt.Errorf("forcedLoginMethod is %q, want %s", login.ForcedMethod, loginMethod)
	}

	return nil
}

// CheckEnv judges the output of `env` in the guest. Messages name a variable, never its value.
func CheckEnv(env string) error {
	var errs []error

	hasPath := false

	for line := range strings.Lines(env) {
		name, _, assigned := strings.Cut(line, "=")
		if !assigned { // the next line of a multi-line value
			continue
		}

		hasPath = hasPath || name == "PATH"

		if IsAgentAuthVar(name) {
			errs = append(errs, fmt.Errorf("%q is set", name))
		}
	}

	if !hasPath {
		errs = append(errs, errors.New("the environment has no PATH, so it wasn't read"))
	}

	return errors.Join(errs...)
}
