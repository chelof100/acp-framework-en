// errors.go — ACP-REP-PORTABILITY-1.1 error sentinels (§9).
package reputation

import "errors"

var (
	// ErrInvalidRequest is returned when a CaptureRequest is malformed.
	ErrInvalidRequest = errors.New("acp/reputation: invalid capture request")

	// ErrInvalidTemporalOrder (REP-001) is returned when evaluated_at > valid_until.
	ErrInvalidTemporalOrder = errors.New("REP-001: evaluated_at > valid_until")

	// ErrScoreOutOfBounds (REP-002) is returned when score is outside scale bounds
	// or when scale is an unsupported value.
	ErrScoreOutOfBounds = errors.New("REP-002: score out of scale")

	// ErrIssuerMissing (REP-004) is returned when issuer is empty.
	ErrIssuerMissing = errors.New("REP-004: issuer missing")

	// ErrInvalidSignature (REP-010) is returned when signature is empty or
	// Ed25519 verification fails.
	ErrInvalidSignature = errors.New("REP-010: invalid signature")

	// ErrExpired (REP-011) is returned when now > valid_until (v1.1 only).
	ErrExpired = errors.New("REP-011: reputation expired")
)
