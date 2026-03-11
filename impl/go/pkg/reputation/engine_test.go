package reputation_test

import (
	"errors"
	"testing"

	"github.com/chelof100/acp-framework/acp-go/pkg/reputation"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func newEngine(t *testing.T) *reputation.Engine {
	t.Helper()
	return reputation.NewDefaultEngine(reputation.NewInMemoryReputationStore())
}

// ─── Cold Start ───────────────────────────────────────────────────────────────

func TestColdStart_ScoreIsNil(t *testing.T) {
	eng := newEngine(t)
	rec, err := eng.GetRecord("agent-new")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if rec.Score != nil {
		t.Fatalf("expected nil Score for cold-start agent, got %v", *rec.Score)
	}
	if rec.State != reputation.StateActive {
		t.Fatalf("expected ACTIVE state, got %s", rec.State)
	}
}

func TestColdStart_FirstEvent_InitializesScore(t *testing.T) {
	eng := newEngine(t)

	if err := eng.RecordEvent("agent-a", reputation.EvtVerifyOK); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	rec, _ := eng.GetRecord("agent-a")
	if rec.Score == nil {
		t.Fatal("expected Score != nil after first event")
	}
	// Cold start: 0.5 + 0.10*0.05 = 0.505
	want := 0.5 + 0.10*0.05
	if diff := *rec.Score - want; diff > 0.0001 || diff < -0.0001 {
		t.Errorf("Score: got %.6f, want %.6f", *rec.Score, want)
	}
}

// ─── EWA Formula ─────────────────────────────────────────────────────────────

func TestEWAFormula_PositiveEvent(t *testing.T) {
	eng := newEngine(t)

	// seed score via a first event
	_ = eng.RecordEvent("agent-b", reputation.EvtAuditPass) // cold start → 0.5 + 0.1*0.10 = 0.510
	rec, _ := eng.GetRecord("agent-b")
	s0 := *rec.Score

	_ = eng.RecordEvent("agent-b", reputation.EvtVerifyOK)
	rec, _ = eng.GetRecord("agent-b")

	// score' = 0.90*s0 + 0.10*0.05
	want := 0.90*s0 + 0.10*0.05
	if diff := *rec.Score - want; diff > 0.0001 || diff < -0.0001 {
		t.Errorf("score after VerifyOK: got %.6f, want %.6f", *rec.Score, want)
	}
}

func TestEWAFormula_NegativeEvent(t *testing.T) {
	eng := newEngine(t)

	// Drive score up first
	for i := 0; i < 5; i++ {
		_ = eng.RecordEvent("agent-c", reputation.EvtAuditPass)
	}

	rec, _ := eng.GetRecord("agent-c")
	s0 := *rec.Score

	_ = eng.RecordEvent("agent-c", reputation.EvtSigInvalid) // -0.30
	rec, _ = eng.GetRecord("agent-c")

	want := 0.90*s0 + 0.10*(-0.30)
	if diff := *rec.Score - want; diff > 0.0001 || diff < -0.0001 {
		t.Errorf("score after SigInvalid: got %.6f, want %.6f", *rec.Score, want)
	}
}

func TestScore_ClampedToZero(t *testing.T) {
	eng := newEngine(t)

	// PolicyViolation on cold start: 0.5 + 0.10*(−0.40) = 0.46 → still ok
	// Apply many policy violations to drive it toward 0.
	for i := 0; i < 50; i++ {
		_ = eng.RecordEvent("agent-d", reputation.EvtPolicyViolation)
	}

	rec, _ := eng.GetRecord("agent-d")
	if *rec.Score < 0.0 {
		t.Errorf("score went below 0: %.6f", *rec.Score)
	}
}

func TestScore_ClampedToOne(t *testing.T) {
	eng := newEngine(t)

	for i := 0; i < 100; i++ {
		_ = eng.RecordEvent("agent-e", reputation.EvtAuditPass)
	}

	rec, _ := eng.GetRecord("agent-e")
	if *rec.Score > 1.0 {
		t.Errorf("score exceeded 1: %.6f", *rec.Score)
	}
}

// ─── State Machine — Automatic Transitions ────────────────────────────────────

func TestTransition_ActiveToProbation(t *testing.T) {
	eng := newEngine(t)

	// Drive score below ProbationThreshold (0.40) from cold-start neutral.
	// Each PolicyViolation: score' = 0.90*s + 0.10*(−0.40)
	for i := 0; i < 20; i++ {
		_ = eng.RecordEvent("agent-prob", reputation.EvtPolicyViolation)
		rec, _ := eng.GetRecord("agent-prob")
		if rec.State == reputation.StateProbation || rec.State == reputation.StateSuspended {
			return // transitioned as expected
		}
	}
	rec, _ := eng.GetRecord("agent-prob")
	t.Fatalf("expected PROBATION or SUSPENDED after many violations, got %s (score %.4f)", rec.State, scoreVal(rec))
}

func TestTransition_ProbationRecovery(t *testing.T) {
	// Mathematical note: with default RecoveryThreshold=0.60, the EWA equilibrium
	// for any positive event is too low to reach recovery.
	// Cold-start baseline gives 0.5 + beta*metric. For AuditPass: 0.51.
	// With RecoveryThreshold=0.50 (minimum allowed), 0.51 >= 0.50 triggers recovery.
	cfg := reputation.DefaultConfig()
	cfg.RecoveryThreshold = 0.50
	eng, err := reputation.NewEngine(reputation.NewInMemoryReputationStore(), cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Admin manually puts a fresh agent in PROBATION (score still nil).
	_ = eng.SetState("agent-rec", reputation.StateProbation, "test", "admin")

	// Cold-start AuditPass: score = 0.5 + 0.10*0.10 = 0.51 >= RecoveryThreshold → ACTIVE.
	if err := eng.RecordEvent("agent-rec", reputation.EvtAuditPass); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	rec, _ := eng.GetRecord("agent-rec")
	if rec.State != reputation.StateActive {
		t.Fatalf("expected ACTIVE after cold-start AuditPass in PROBATION, got %s (score %.4f)",
			rec.State, scoreVal(rec))
	}
}

func TestTransition_SuspendedNoAutoTransition(t *testing.T) {
	eng := newEngine(t)
	_ = eng.SetState("agent-sus", reputation.StateSuspended, "test", "admin")

	// Even with good events, SUSPENDED should not auto-recover.
	for i := 0; i < 20; i++ {
		_ = eng.RecordEvent("agent-sus", reputation.EvtAuditPass)
	}

	rec, _ := eng.GetRecord("agent-sus")
	if rec.State != reputation.StateSuspended {
		t.Fatalf("SUSPENDED should not auto-transition, got %s", rec.State)
	}
}

// ─── BANNED (terminal) ────────────────────────────────────────────────────────

func TestBanned_TerminalState(t *testing.T) {
	eng := newEngine(t)
	_ = eng.SetState("agent-ban", reputation.StateBanned, "critical violation", "admin")

	err := eng.RecordEvent("agent-ban", reputation.EvtVerifyOK)
	if !errors.Is(err, reputation.ErrAgentBanned) {
		t.Fatalf("expected ErrAgentBanned on RecordEvent for BANNED agent, got: %v", err)
	}
}

func TestBanned_CannotChangeState(t *testing.T) {
	eng := newEngine(t)
	_ = eng.SetState("agent-ban2", reputation.StateBanned, "critical", "admin")

	err := eng.SetState("agent-ban2", reputation.StateActive, "try to unban", "admin")
	if !errors.Is(err, reputation.ErrAgentBanned) {
		t.Fatalf("expected ErrAgentBanned on SetState for BANNED agent, got: %v", err)
	}
}

// ─── SetState validation ──────────────────────────────────────────────────────

func TestSetState_RequiresReason(t *testing.T) {
	eng := newEngine(t)
	err := eng.SetState("agent-x", reputation.StateProbation, "", "admin")
	if err == nil {
		t.Fatal("expected error for empty reason")
	}
}

func TestSetState_RequiresAuthorizedBy(t *testing.T) {
	eng := newEngine(t)
	err := eng.SetState("agent-x", reputation.StateProbation, "some reason", "")
	if err == nil {
		t.Fatal("expected error for empty authorizedBy")
	}
}

// ─── UnknownEventType ─────────────────────────────────────────────────────────

func TestRecordEvent_UnknownType(t *testing.T) {
	eng := newEngine(t)
	err := eng.RecordEvent("agent-y", "REP_EVT_NONEXISTENT")
	if !errors.Is(err, reputation.ErrUnknownEventType) {
		t.Fatalf("expected ErrUnknownEventType, got: %v", err)
	}
}

// ─── Config validation ────────────────────────────────────────────────────────

func TestNewEngine_InvalidAlpha(t *testing.T) {
	cfg := reputation.DefaultConfig()
	cfg.Alpha = 0.50 // out of [0.80, 0.99]
	_, err := reputation.NewEngine(reputation.NewInMemoryReputationStore(), cfg)
	if !errors.Is(err, reputation.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for invalid alpha, got: %v", err)
	}
}

func TestNewEngine_SuspensionThresholdGEProbation(t *testing.T) {
	cfg := reputation.DefaultConfig()
	cfg.SuspensionThreshold = cfg.ProbationThreshold // must be strictly less
	_, err := reputation.NewEngine(reputation.NewInMemoryReputationStore(), cfg)
	if !errors.Is(err, reputation.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig when suspension >= probation, got: %v", err)
	}
}

// ─── Pagination ───────────────────────────────────────────────────────────────

func TestGetEvents_MostRecentFirst(t *testing.T) {
	eng := newEngine(t)

	events := []string{
		reputation.EvtVerifyOK,
		reputation.EvtAuditPass,
		reputation.EvtSigLate,
	}
	for _, e := range events {
		_ = eng.RecordEvent("agent-pag", e)
	}

	got, total, err := eng.GetEvents("agent-pag", 10, 0)
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if total != 3 {
		t.Fatalf("total: got %d, want 3", total)
	}
	// Most recent first = SigLate, AuditPass, VerifyOK
	if got[0].EventType != reputation.EvtSigLate {
		t.Errorf("got[0] should be most recent (%s), got %s", reputation.EvtSigLate, got[0].EventType)
	}
}

func TestGetEvents_Pagination(t *testing.T) {
	eng := newEngine(t)

	for i := 0; i < 10; i++ {
		_ = eng.RecordEvent("agent-pages", reputation.EvtVerifyOK)
	}

	got, total, err := eng.GetEvents("agent-pages", 3, 2)
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if total != 10 {
		t.Fatalf("total: got %d, want 10", total)
	}
	if len(got) != 3 {
		t.Fatalf("len(events): got %d, want 3", len(got))
	}
}

// ─── Helper ───────────────────────────────────────────────────────────────────

func scoreVal(rec *reputation.ReputationRecord) float64 {
	if rec.Score == nil {
		return -1
	}
	return *rec.Score
}
