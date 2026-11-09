// Command bomhort-import moves an existing SBOM inventory into BOMHort (#536).
//
// It reads CycloneDX documents with embedded vulnerabilities[].analysis,
// uploads each SBOM and one OpenVEX document with its triage decisions
// through POST /api/v1/sboms/upload. It needs only the instance URL and an
// API key, never database access. Rerunning it imports nothing twice.
//
//	BOMHORT_API_KEY=... bomhort-import --dir ./export --url https://bomhort.example.com
//	bomhort-import --dir ./export --mapping mapping.json --dry-run
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/importer"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		source      = flag.String("source", "dir", "where to read from; only \"dir\" is supported")
		dir         = flag.String("dir", "", "directory of CycloneDX JSON documents (read recursively)")
		baseURL     = flag.String("url", os.Getenv("BOMHORT_URL"), "BOMHort base URL, e.g. https://bomhort.example.com (default $BOMHORT_URL)")
		mappingPath = flag.String("mapping", "", "JSON file assigning BOMHort project and tags to source projects")
		dryRun      = flag.Bool("dry-run", false, "print what would be imported without uploading")
		timeout     = flag.Duration("timeout", 2*time.Minute, "timeout per upload request")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: bomhort-import --dir DIR (--url URL | --dry-run) [flags]\n\nThe API key is read from $BOMHORT_API_KEY.\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *source != "dir" {
		fmt.Fprintf(os.Stderr, "unsupported --source %q: only \"dir\" is supported\n", *source)
		return 2
	}
	if *dir == "" {
		flag.Usage()
		return 2
	}
	src, err := importer.NewDirSource(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	var mapping *importer.Mapping
	if *mappingPath != "" {
		if mapping, err = importer.LoadMapping(*mappingPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}

	opts := importer.Options{Source: src, Mapping: mapping, Out: os.Stdout}
	if !*dryRun {
		client, err := importer.NewClient(*baseURL, os.Getenv("BOMHORT_API_KEY"), *timeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		opts.Uploader = client
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	sum, err := importer.Run(ctx, opts)
	for _, s := range src.Skipped {
		fmt.Printf("skipped %s\n", s)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if *dryRun {
		fmt.Printf("\nDry run: %d SBOMs and %d VEX documents (%d statements) would be uploaded.\n",
			sum.Projects, sum.VEX, sum.Statements)
	} else {
		fmt.Printf("\n%d SBOMs read, %d documents uploaded, %d already imported, %d failed.\n",
			sum.Projects, sum.Uploaded, sum.Duplicates, sum.Failed)
	}
	if sum.Failed > 0 {
		return 1
	}
	return 0
}
