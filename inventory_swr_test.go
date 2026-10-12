package teainsights

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The Insights inventory is built once however many requests ask, served stale
// while its replacement is built, and a build is never tied to one request.
func TestTeaInsightsInventoryServedStaleWhileRebuilding(t *testing.T) {
	const org = "org-swr-test"
	oldBuild := BuildFunc
	defer func() { BuildFunc = oldBuild }()
	teaInsightsCache.Delete(org)
	teaInsightsLastTry.Delete(org)

	var builds atomic.Int32
	release := make(chan struct{})
	BuildFunc = func(ctx context.Context, q Querier, seeds Seeds) (*Inventory, error) {
		n := builds.Add(1)
		if n > 1 {
			<-release // the rebuild is slow
		}
		return &Inventory{OrgID: org, BuiltAt: time.Now()}, nil
	}
	seeds := Seeds{OrgID: org}

	// Ten concurrent first requests share one build.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := LoadInventory(context.Background(), nil, seeds); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := builds.Load(); got != 1 {
		t.Fatalf("builds after 10 concurrent cold requests = %d, want 1", got)
	}

	// A request inside the TTL is a cache hit.
	if _, err := LoadInventory(context.Background(), nil, seeds); err != nil || builds.Load() != 1 {
		t.Fatalf("fresh hit rebuilt (builds=%d err=%v)", builds.Load(), err)
	}

	// Age the entry past its TTL: the stale inventory answers immediately and a
	// rebuild starts behind it.
	v, _ := teaInsightsCache.Get(org)
	stale := v.(*Inventory)
	stale.BuiltAt = time.Now().Add(-2 * teaInsightsTTL)
	start := time.Now()
	got, err := LoadInventory(context.Background(), nil, seeds)
	if err != nil || got != stale {
		t.Fatalf("a stale inventory must be served as is: %v %v", got, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the stale answer waited for the rebuild")
	}
	// Further stale requests do not start more rebuilds.
	for i := 0; i < 5; i++ {
		_, _ = LoadInventory(context.Background(), nil, seeds)
	}
	deadline := time.Now().Add(2 * time.Second)
	for builds.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := builds.Load(); got != 2 {
		t.Fatalf("builds = %d, want exactly one background rebuild", got)
	}
	close(release)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v, _ := teaInsightsCache.Get(org); v.(*Inventory) != stale {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the rebuilt inventory never replaced the stale one")
}

// A caller whose request ends does not fail the build for the others, and a failed
// build is an error to the caller that needed it.
func TestTeaInsightsInventoryBuildOutlivesTheRequest(t *testing.T) {
	const org = "org-swr-cancel"
	oldBuild := BuildFunc
	defer func() { BuildFunc = oldBuild }()
	teaInsightsCache.Delete(org)
	teaInsightsLastTry.Delete(org)

	gate := make(chan struct{})
	BuildFunc = func(ctx context.Context, q Querier, seeds Seeds) (*Inventory, error) {
		<-gate
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &Inventory{OrgID: org, BuiltAt: time.Now()}, nil
	}
	seeds := Seeds{OrgID: org}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := LoadInventory(ctx, nil, seeds); done <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancelled caller got %v", err)
	}
	close(gate)
	// Another caller still gets the inventory the first one started.
	got, err := LoadInventory(context.Background(), nil, seeds)
	if err != nil || got == nil || got.OrgID != org {
		t.Fatalf("second caller: %v %v", got, err)
	}
}
