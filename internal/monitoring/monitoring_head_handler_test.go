package monitoring

import (
	"context"
	"testing"

	"github.com/stakefish/eth2-monitor/internal/spec"

	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func headEvent(epoch phase0.Epoch) *v1.Event {
	return &v1.Event{Topic: "head", Data: &v1.HeadEvent{Slot: spec.EpochLowestSlot(epoch)}}
}

// TestHeadEventHandler_EmitsEndedEpochs pins the happy path the guard
// test below must not break: a head in epoch 12 with lastEpoch 10 emits
// 10 and 11 and advances lastEpoch.
func TestHeadEventHandler_EmitsEndedEpochs(t *testing.T) {
	ch := make(chan phase0.Epoch, 4)
	last := phase0.Epoch(10)
	handler := newHeadEventHandler(context.Background(), ch, &last)

	handler(headEvent(12))

	if got := []phase0.Epoch{<-ch, <-ch}; got[0] != 10 || got[1] != 11 {
		t.Fatalf("emitted epochs = %v, want [10 11]", got)
	}
	if last != 12 {
		t.Fatalf("lastEpoch = %d, want 12", last)
	}
}

// TestHeadEventHandler_AfterChannelCloseDoesNotPanic: go-eth2-client's
// SSE goroutine can deliver one more head event after SubscribeToEpochs
// has returned and closed the epoch channel, and the send would panic
// ("send on closed channel"). A late event must be dropped, not crash
// the process.
func TestHeadEventHandler_AfterChannelCloseDoesNotPanic(t *testing.T) {
	ch := make(chan phase0.Epoch)
	close(ch)
	last := phase0.Epoch(10)
	handler := newHeadEventHandler(context.Background(), ch, &last)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked on a head event after channel close: %v", r)
		}
	}()
	handler(headEvent(12))
}
