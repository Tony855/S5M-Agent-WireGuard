package keyedlock

import (
	"context"
	"errors"
	"sync"
)

var ErrInvalidKey = errors.New("keyed lock key is required")

type entry struct {
	token chan struct{}
	refs  int
}

// Locks provides context-aware, per-key mutual exclusion. Entries are removed
// after the final holder/waiter releases its reference.
type Locks struct {
	mu      sync.Mutex
	entries map[string]*entry
}

func (l *Locks) Acquire(ctx context.Context, key string) (func(), error) {
	if key == "" {
		return nil, ErrInvalidKey
	}
	if ctx == nil {
		return nil, errors.New("lock context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l.mu.Lock()
	if l.entries == nil {
		l.entries = make(map[string]*entry)
	}
	current := l.entries[key]
	if current == nil {
		current = &entry{token: make(chan struct{}, 1)}
		l.entries[key] = current
	}
	current.refs++
	l.mu.Unlock()

	select {
	case current.token <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-current.token
			l.release(key, current)
			return nil, err
		}
		var once sync.Once
		return func() {
			once.Do(func() {
				<-current.token
				l.release(key, current)
			})
		}, nil
	case <-ctx.Done():
		l.release(key, current)
		return nil, ctx.Err()
	}
}

func (l *Locks) release(key string, current *entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries[key] != current {
		return
	}
	current.refs--
	if current.refs == 0 {
		delete(l.entries, key)
	}
}
