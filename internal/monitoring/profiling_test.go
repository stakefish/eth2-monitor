package monitoring

import (
	"testing"
)

// TestMeasure_LogsOnNormalReturn — sanity-check: the function runs to
// completion without panicking when the handler is well-behaved.
func TestMeasure_LogsOnNormalReturn(t *testing.T) {
	called := false
	Measure(func() { called = true }, "test")
	if !called {
		t.Error("handler was not called")
	}
}

// TestMeasure_LogsOnPanic regresses the missing-telemetry case: a panicking
// handler must still fire the elapsed-time log via the deferred Measure
// call, then re-panic up to the caller. Without `defer`, the panic
// short-circuits before log emission and operators lose the timing data
// for the very operation that failed.
func TestMeasure_LogsOnPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic to propagate, got nil")
		}
		if got, ok := r.(string); !ok || got != "boom" {
			t.Errorf("recovered value = %v, want \"boom\"", r)
		}
	}()
	Measure(func() { panic("boom") }, "test")
}
