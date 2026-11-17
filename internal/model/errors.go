package model

import (
	"fmt"
	"regexp"
)

type Error struct {
	Code    string
	Message string
	HTTP    int
}

func (e *Error) Error() string { return e.Message }
func Invalid(format string, args ...any) error {
	return &Error{"invalid_input", fmt.Sprintf(format, args...), 400}
}
func Missing(kind, id string) error {
	return &Error{"not_found", fmt.Sprintf("%s %s does not exist", kind, id), 404}
}
func Conflict(message string) error { return &Error{"conflict", message, 409} }

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$`)

func ValidateID(id string) error {
	if !identifier.MatchString(id) {
		return Invalid("identifier must use 1-80 letters, digits, dots, dashes or underscores")
	}
	return nil
}
func NewState() State {
	return State{Version: 1, Certificates: map[string]Certificate{}, TrustSets: map[string]TrustSet{}, Artifacts: map[string]Artifact{}, Signatures: map[string]Signature{}, Revocations: map[string]RevocationList{}, OCSPResponders: map[string]OCSPResponder{}, OCSPResponses: map[string]OCSPResponse{}, Policies: map[string][]Policy{}, Decisions: map[string]Decision{}, Materials: map[string]Material{}, Events: []Event{}}
}
