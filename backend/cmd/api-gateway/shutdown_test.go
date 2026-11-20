package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestServerGracefulShutdown verifies that:
// 1. In-flight requests are allowed to complete during server shutdown.
// 2. The server exits cleanly within the shutdown timeout.
// 3. New incoming requests are rejected after shutdown is initiated.
func TestServerGracefulShutdown(t *testing.T) {
	reqStarted := make(chan struct{})
	reqRelease := make(chan struct{})
	reqDone := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(reqStarted)
		<-reqRelease
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("slow-completed"))
		close(reqDone)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	addr := listener.Addr().String()

	// 1. Start an in-flight slow request.
	var clientResp *http.Response
	var clientErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		client := &http.Client{Timeout: 10 * time.Second}
		clientResp, clientErr = client.Get("http://" + addr + "/slow")
	}()

	select {
	case <-reqStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for slow request to reach handler")
	}

	// 2. Initiate graceful shutdown with a bounded context.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- srv.Shutdown(shutdownCtx)
	}()

	// 3. Release the in-flight request so it can finish while shutdown is pending.
	close(reqRelease)

	select {
	case <-reqDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for in-flight request to finish")
	}

	wg.Wait()
	if clientErr != nil {
		t.Fatalf("client request failed during graceful shutdown: %v", clientErr)
	}
	defer clientResp.Body.Close()

	body, err := io.ReadAll(clientResp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(body) != "slow-completed" {
		t.Fatalf("unexpected body: got %q, want %q", string(body), "slow-completed")
	}

	// 4. Verify Shutdown completed without error.
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Shutdown to complete")
	}

	// 5. Subsequent requests to the listener should fail because the listener is closed.
	newClient := &http.Client{Timeout: 1 * time.Second}
	_, err = newClient.Get("http://" + addr + "/slow")
	if err == nil {
		t.Fatal("expected request after shutdown to fail, but it succeeded")
	}
}
