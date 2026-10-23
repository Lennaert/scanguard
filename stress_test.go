package scanguard

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentStress hammers one guard from many goroutines: scans, honest
// traffic, manual bans and unbans, with the clock moving. Run with -race.
func TestConcurrentStress(t *testing.T) {
	var actions atomic.Int32
	g, h, clk := newTestGuard(t, func(c *Config) {
		c.Actions = []Action{ActionFunc(func(context.Context, Event) error { actions.Add(1); return nil })}
	})
	ctx := context.Background()
	paths := []string{"/.env", "/wp-login.php", "/gone", "/static/app.js", "/", "/admin"}

	var wg sync.WaitGroup
	for w := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				ip := fmt.Sprintf("203.0.%d.%d", w%4, i%50)
				switch {
				case i%97 == 0:
					g.Unban(ctx, ip)
				case i%89 == 0:
					g.Ban(ctx, ip, "manual")
				case i%500 == 0:
					clk.add(30 * time.Second)
				default:
					get(h, ip, paths[(w+i)%len(paths)])
				}
			}
		}()
	}
	wg.Wait()
	if err := g.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if actions.Load() == 0 {
		t.Fatal("expected some bans")
	}
}

// TestOneBanPerBurst checks that a burst of simultaneous scanner requests
// from one IP produces exactly one ban and one offense.
func TestOneBanPerBurst(t *testing.T) {
	for round := range 50 {
		var mu sync.Mutex
		var evs []Event
		g, h, _ := newTestGuard(t, func(c *Config) {
			c.Actions = []Action{ActionFunc(func(_ context.Context, ev Event) error {
				mu.Lock()
				evs = append(evs, ev)
				mu.Unlock()
				return nil
			})}
		})
		var start sync.WaitGroup
		start.Add(1)
		var wg sync.WaitGroup
		for range 100 {
			wg.Add(1)
			go func() { defer wg.Done(); start.Wait(); get(h, "203.0.113.7", "/.env") }()
		}
		start.Done()
		wg.Wait()
		g.Shutdown(context.Background())
		if len(evs) != 1 || evs[0].Offense != 1 {
			t.Fatalf("round %d: got %d bans (%+v), want exactly one first offense", round, len(evs), evs)
		}
		if code := get(h, "203.0.113.7", "/"); code != http.StatusForbidden {
			t.Fatalf("round %d: got %d, want 403", round, code)
		}
	}
}
