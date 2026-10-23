package scanguard_test

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/Lennaert/scanguard"
)

func Example() {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello"))
	})

	guard, err := scanguard.New(scanguard.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe(":8080", guard.Middleware(mux)))
}

func Example_behindCloudflare() {
	cfg := scanguard.DefaultConfig()
	cfg.ClientIP = scanguard.HeaderIP("CF-Connecting-IP")
	cfg.BanDurations = []time.Duration{10 * time.Minute, 24 * time.Hour}

	guard, err := scanguard.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	_ = guard
}

func ExampleActionFunc() {
	cfg := scanguard.DefaultConfig()
	cfg.Actions = []scanguard.Action{
		scanguard.ActionFunc(func(ctx context.Context, ev scanguard.Event) error {
			slog.Warn("scanner banned", "ip", ev.IP, "offense", ev.Offense, "until", ev.Until)
			return nil
		}),
	}
	if _, err := scanguard.New(cfg); err != nil {
		log.Fatal(err)
	}
}

func ExampleMatch() {
	fmt.Println(scanguard.Match("/admin", "/admin/users"))
	fmt.Println(scanguard.Match("/admin", "/administrators-guide"))
	fmt.Println(scanguard.Match(".php", "/index.php"))
	// Output:
	// true
	// false
	// true
}
