package main

// webscan: URL 을 받아 가져오고 스캔해 결과를 JSON 으로 돌려주는 API 서버.

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/suseong41/suseong-html-analyzer/fetcher"
	"github.com/suseong41/suseong-html-analyzer/web"
)

func main() {
	// 기본은 127.0.0.1 - 0.0.0.0 으로 열려면 명시해야 함.
	addr := flag.String("addr", "127.0.0.1:8080", "들을 주소")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           web.New(&fetcher.Fetcher{}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("http://%s", *addr)
	log.Fatal(srv.ListenAndServe())
}
