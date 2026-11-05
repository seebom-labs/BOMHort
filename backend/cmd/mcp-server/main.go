// Command mcp-server exposes BOMHort's read-only data as MCP tools (#399).
//
// It is the fifth binary of the platform and the only one that talks to no
// database: it calls the REST API of the api-gateway like any other external
// consumer. That is deliberate. The MCP server is the first consumer of the
// contract that 1.0 freezes, and a consumer that reaches around the contract
// would not exercise it.
//
// Transports:
//
//	stdio (default) — the client starts this binary and speaks over the pipe.
//	                  Nothing is listening on a port; this is what an MCP
//	                  client on a laptop wants.
//	http            — Streamable HTTP, opt-in, and refused unless a bearer
//	                  token and an explicit Origin allow-list are configured.
//
// No write tools, and no LLM calls: BOMHort never calls a model itself, it is
// the thing a model asks.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/seebom-labs/bomhort/backend/internal/apiclient"
	"github.com/seebom-labs/bomhort/backend/internal/config"
)

// version is the server version reported in the MCP initialize handshake.
// Overridden at build time with -ldflags "-X main.version=v0.8.0".
var version = "dev"

// shutdownGrace bounds how long an in-flight HTTP session may finish.
const shutdownGrace = 10 * time.Second

func main() {
	// stdio is a protocol channel: anything written to stdout corrupts the
	// JSON-RPC stream. Logging goes to stderr for every transport, so that the
	// two modes cannot behave differently in this respect.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("FATAL: failed to load config: %v", err)
	}

	client, err := apiclient.New(apiclient.Options{
		BaseURL:      cfg.MCPAPIBaseURL,
		APIKey:       cfg.MCPAPIKey,
		ServiceToken: cfg.MCPServiceToken,
		Timeout:      time.Duration(cfg.MCPRequestTimeout) * time.Second,
		UserAgent:    "bomhort-mcp-server/" + version,
	})
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "bomhort",
		Title:   "BOMHort",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: instructions,
	})
	registerTools(server, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// One probe before serving. A wrong base URL or a missing token is a
	// startup failure the operator can see, instead of five tool calls failing
	// inside someone's agent transcript with no explanation.
	probeCtx, probeCancel := context.WithTimeout(ctx, time.Duration(cfg.MCPRequestTimeout)*time.Second)
	err = client.Health(probeCtx)
	probeCancel()
	if err != nil {
		log.Printf("WARN: BOMHort API at %s is not answering yet: %v", client.BaseURL(), err)
	} else {
		log.Printf("Connected to BOMHort API at %s", client.BaseURL())
	}

	switch cfg.MCPTransport {
	case config.MCPTransportStdio:
		log.Printf("BOMHort MCP server %s ready on stdio (5 read-only tools)", version)
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("FATAL: mcp server: %v", err)
		}
	case config.MCPTransportHTTP:
		if err := serveHTTP(ctx, server, cfg); err != nil {
			log.Fatalf("FATAL: %v", err)
		}
	default:
		// config.Load validates the enum; this is the unreachable branch.
		log.Fatalf("FATAL: unsupported MCP_TRANSPORT %q", cfg.MCPTransport)
	}

	log.Println("MCP server stopped.")
}

// serveHTTP runs the Streamable HTTP transport. It refuses to start without
// both a bearer token and an explicit Origin allow-list: an unauthenticated
// MCP endpoint is remote tool execution for anyone who can reach the port, and
// "*" would re-open the cross-site hole (CVE-2026-33252) the SDK pin closes.
func serveHTTP(ctx context.Context, server *mcp.Server, cfg *config.Config) error {
	if cfg.MCPHTTPToken == "" {
		return fmt.Errorf("MCP_TRANSPORT=http requires MCP_HTTP_TOKEN: an unauthenticated MCP endpoint is remote tool execution")
	}
	if len(cfg.MCPAllowedOrigins) == 0 {
		return fmt.Errorf("MCP_TRANSPORT=http requires MCP_ALLOWED_ORIGINS: an explicit list, because a browser page must not be able to drive this server")
	}
	for _, o := range cfg.MCPAllowedOrigins {
		if strings.TrimSpace(o) == "*" {
			return fmt.Errorf("MCP_ALLOWED_ORIGINS must not contain '*': list the origins explicitly")
		}
	}

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)

	srv := &http.Server{
		Addr:              cfg.MCPHTTPAddr,
		Handler:           httpGuard(handler, cfg.MCPHTTPToken, cfg.MCPAllowedOrigins),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("BOMHort MCP server %s listening on %s (Streamable HTTP, %d allowed origins)",
			version, cfg.MCPHTTPAddr, len(cfg.MCPAllowedOrigins))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// instructions is sent to the client at initialize. It states the two things
// a model cannot infer from the schemas and will otherwise get wrong: that
// project counts are de-duplicated across versions, and that a suppressed
// finding is returned rather than hidden.
const instructions = `BOMHort is an SBOM and supply-chain governance platform.

Use list_projects to discover what this instance knows about, get_project for
one project as a unit, search_packages to find who ships a component,
list_vulnerabilities for findings, get_affected_projects for the blast radius
of one vulnerability, get_dashboard_stats for instance totals and get_sbom for
a single document.

Two things to keep in mind when reporting numbers:

  * Project counts are de-duplicated across versions. A package present in ten
    versions of a project counts once, and so does a finding. Do not add up
    per-version numbers to get a project total.
  * Vulnerability listings include findings that VEX marks as not_affected or
    fixed. Check vex_status before calling a finding open; a finding with
    vex_status "not_affected" is documented as not exploitable, not ignored.

This server is read-only. It cannot upload SBOMs, write VEX statements or
change policy; those are config-file and upload-API operations.`
