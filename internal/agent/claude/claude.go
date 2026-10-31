// Package claude reads the output of Claude Code's commands and returns structured data.
package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

const backgroundKind = "background"

// Login is the login state from `claude auth status --json`.
type Login struct {
	LoggedIn     bool
	Method       string
	ForcedMethod string // the forced login method, from any settings source; empty if none
}

// ParseLogin reads the output of `claude auth status --json`.
func ParseLogin(out []byte) (Login, error) {
	var doc struct {
		LoggedIn          *bool  `json:"loggedIn"`
		AuthMethod        string `json:"authMethod"`
		ForcedLoginMethod string `json:"forcedLoginMethod"`
	}

	if err := json.Unmarshal(out, &doc); err != nil {
		return Login{}, fmt.Errorf("parsing claude auth status: %w", err)
	}

	if doc.LoggedIn == nil {
		return Login{}, errors.New("parsing claude auth status: no loggedIn field")
	}

	return Login{LoggedIn: *doc.LoggedIn, Method: doc.AuthMethod, ForcedMethod: doc.ForcedLoginMethod}, nil
}

// Session is one background session from `claude agents --json`.
type Session struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Cwd   string `json:"cwd"`
	State string `json:"state"`
}

// ParseSessions reads the output of `claude agents --json` and returns only the background sessions.
func ParseSessions(out []byte) ([]Session, error) {
	var sessions []Session
	if err := json.Unmarshal(out, &sessions); err != nil {
		return nil, fmt.Errorf("parsing claude agents: %w", err)
	}

	return slices.DeleteFunc(sessions, func(s Session) bool { return s.Kind != backgroundKind }), nil
}
