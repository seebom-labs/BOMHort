package main

import (
	"context"
	"log"
	"net/http"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

// upstreamVEXSyncer pulls upstream VEX statements and inserts them.
// Interface allows unit testing without a ClickHouse instance.
type upstreamVEXSyncer interface {
	SyncUpstreamVEX(ctx context.Context, sources []config.VEXSourceConfig) (int, error)
}

// upstreamVEXSyncHandler triggers on-demand upstream VEX sync (#538).
func upstreamVEXSyncHandler(cfg *config.Config, syncer upstreamVEXSyncer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Mutating endpoint: require AUTH_ENABLED=true, matching upload and PATCH handlers.
		if !cfg.AuthEnabled {
			writeError(w, http.StatusForbidden, "Upstream VEX sync requires AUTH_ENABLED=true")
			return
		}

		if !cfg.HasVEXSources() {
			writeJSON(w, http.StatusOK, map[string]any{
				"applied": 0,
				"status":  "no upstream VEX sources configured",
			})
			return
		}

		applied, err := syncer.SyncUpstreamVEX(r.Context(), cfg.VEXSources)
		if err != nil {
			log.Printf("ERROR: upstream vex sync: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to sync upstream VEX: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"applied": applied,
			"status":  "ok",
		})
	}
}
