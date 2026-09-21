package main

// webscan: URL 을 받아 가져오고 스캔해 결과를 JSON 으로 돌려주는 API 서버.

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/suseong41/sha/fetcher"
	"github.com/suseong41/sha/version"
	"github.com/suseong41/sha/web"
)

func main() {
	// 기본은 127.0.0.1 - 0.0.0.0 으로 열려면 명시해야 함.
	addr := flag.String("addr", "127.0.0.1:8080", "들을 주소")
	maxScans := flag.Int("max-scans", web.DefaultMaxScans, "동시에 처리할 스캔 수")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           web.New(&fetcher.Fetcher{}, logger, *maxScans),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	logger.Info("listening", "addr", *addr, "version", version.V, "max_scans", *maxScans)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
