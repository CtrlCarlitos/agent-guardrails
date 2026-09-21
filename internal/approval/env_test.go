package approval

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func setStateHome(t testing.TB, root string) {
	t.Helper()
	testenv.SetState(t, root)
}
