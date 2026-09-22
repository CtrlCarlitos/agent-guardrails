package session

import (
	"context"
	"sync"
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
// processes. The caller's lock deadline bounds time spent in both layers.
func acquireLocalTransactionGate(ctx context.Context, lockPath string) (func(), error) {
	localTransactionGates.Lock()
	gate := localTransactionGates.byPath[lockPath]
	if gate == nil {
		gate = &transactionGate{token: make(chan struct{}, 1)}
		gate.token <- struct{}{}
		localTransactionGates.byPath[lockPath] = gate
	}
	gate.users++
	localTransactionGates.Unlock()

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
