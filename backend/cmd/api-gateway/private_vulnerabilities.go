package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/internal/privatevuln"
	"github.com/seebom-labs/bomhort/backend/internal/rulesource"
)

// requestPrivateVulnerabilities returns the private vulnerability index a request
// should be answered with.
func requestPrivateVulnerabilities(w http.ResponseWriter, watcher *privatevuln.Watcher) (*privatevuln.Index, bool) {
	s := watcher.Current()
	switch {
	case errors.Is(s.Err, rulesource.ErrInvalid):
		log.Printf("ERROR: private vulnerabilities configuration: %v", s.Err)
		writeError(w, http.StatusInternalServerError, "Invalid private vulnerabilities configuration")
		return nil, false
	case !s.Ready:
		log.Printf("ERROR: private vulnerabilities not loaded yet: %v", s.Err)
		writeError(w, http.StatusServiceUnavailable, "Private vulnerabilities are not available yet")
		return nil, false
	}
	return s.Value, true
}

// privateVulnerabilitiesHandler serves the active private vulnerability advisories.
func privateVulnerabilitiesHandler(watcher *privatevuln.Watcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idx, ok := requestPrivateVulnerabilities(w, watcher)
		if !ok {
			return
		}
		if idx == nil || len(idx.ActiveEntries) == 0 {
			writeJSON(w, http.StatusOK, []osv.VulnEntry{})
			return
		}
		writeJSON(w, http.StatusOK, idx.ActiveEntries)
	}
}

// watchPrivateVulnerabilities loads private vulnerability advisories once and keeps
// them current.
func watchPrivateVulnerabilities(ctx context.Context, opts rulesource.Options, interval time.Duration) (*privatevuln.Watcher, error) {
	watcher, err := privatevuln.Watch(opts)
	if err != nil {
		return nil, err
	}
	if _, err := watcher.Refresh(ctx); err != nil {
		log.Printf("ERROR: private vulnerabilities from %s: %v", watcher.Current().Source, err)
	}
	go watcher.Run(ctx, interval, func(s rulesource.Snapshot[*privatevuln.Index]) {
		log.Printf("Private vulnerabilities reloaded from %s (%s)", s.Source, s.Digest[:12])
	})
	return watcher, nil
}
