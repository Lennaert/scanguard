// Command example runs a tiny server guarded by scanguard.
//
//	go run ./example
//	for p in /.env /.git/config /wp-login.php /phpmyadmin/ /backup.sql /; do
//	  curl -s -o /dev/null -w "%{http_code} $p\n" -H 'X-Real-IP: 203.0.113.7' localhost:8080$p
//	done
package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"

	"github.com/Lennaert/scanguard"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello\n"))
	})

	cfg := scanguard.DefaultConfig()
	// Demo only: trust X-Real-IP so curl from localhost can pretend to be
	// someone else. In production, trust only what your proxy sets.
	cfg.ClientIP = scanguard.HeaderIP("X-Real-IP")
	cfg.Actions = []scanguard.Action{
		scanguard.ActionFunc(func(_ context.Context, ev scanguard.Event) error {
			slog.Info("would tell Slack/Cloudflare here", "ip", ev.IP, "path", ev.Path)
			return nil
		}),
	}

	guard, err := scanguard.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", guard.Middleware(mux)))
}
