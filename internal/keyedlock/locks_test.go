package keyedlock

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAcquireSerializesSameKeyAndAllowsDifferentKeys(t *testing.T) {
	var locks Locks
	releaseFirst, err := locks.Acquire(context.Background(), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFirst()

	releaseOther, err := locks.Acquire(context.Background(), "wg1")
	if err != nil {
		t.Fatalf("different key should not block: %v", err)
	}
	releaseOther()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := locks.Acquire(ctx, "wg0"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same-key waiter error = %v, want deadline exceeded", err)
	}
}

func TestAcquireCanProceedAfterCanceledWaiter(t *testing.T) {
	var locks Locks
	release, err := locks.Acquire(context.Background(), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := locks.Acquire(ctx, "wg0"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled acquire error = %v", err)
	}
	release()

	next, err := locks.Acquire(context.Background(), "wg0")
	if err != nil {
		t.Fatalf("lock remained blocked after release: %v", err)
	}
	next()
}

func TestAcquireRejectsEmptyKeyAndNilContext(t *testing.T) {
	var locks Locks
	if _, err := locks.Acquire(context.Background(), ""); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("empty key error = %v", err)
	}
	if _, err := locks.Acquire(nil, "wg0"); err == nil {
		t.Fatal("nil context must be rejected")
	}
}
