package session

import (
	"context"
	"sync"
	"time"
)

type transactionGate struct {
	token chan struct{}
	users int
}

var localTransactionGates = struct {
	sync.Mutex
	byPath map[string]*transactionGate
}{byPath: make(map[string]*transactionGate)}

// acquireLocalTransactionGate queues callers in this process before they
// contend for the store-wide OS lock. In particular, this avoids a Windows
// LockFileEx retry stampede while the file lock continues to serialize other
// processes.
//
// Each caller ahead may legitimately consume one lock-acquisition budget, so
// the local wait scales with the observed queue depth. Once admitted, the
// caller receives a fresh OS-lock budget in Transaction. Sharing one deadline
// between these layers made tail callers time out under full-suite load before
// they ever attempted LockFileEx (#250).
func acquireLocalTransactionGate(lockPath string, waitPerCaller time.Duration) (func(), error) {
	localTransactionGates.Lock()
	gate := localTransactionGates.byPath[lockPath]
	if gate == nil {
		gate = &transactionGate{token: make(chan struct{}, 1)}
		gate.token <- struct{}{}
		localTransactionGates.byPath[lockPath] = gate
	}
	gate.users++
	queueDepth := gate.users
	localTransactionGates.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(queueDepth)*waitPerCaller)
	defer cancel()

	select {
	case <-gate.token:
		return func() {
			gate.token <- struct{}{}
			releaseLocalTransactionGate(lockPath, gate)
		}, nil
	case <-ctx.Done():
		releaseLocalTransactionGate(lockPath, gate)
		return nil, ctx.Err()
	}
}

func releaseLocalTransactionGate(lockPath string, gate *transactionGate) {
	localTransactionGates.Lock()
	defer localTransactionGates.Unlock()
	gate.users--
	if gate.users == 0 && localTransactionGates.byPath[lockPath] == gate {
		delete(localTransactionGates.byPath, lockPath)
	}
}
