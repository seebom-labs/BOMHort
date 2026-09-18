package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/docstore"
	gh "github.com/seebom-labs/bomhort/backend/internal/github"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/internal/osvutil"
	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
	"github.com/seebom-labs/bomhort/backend/internal/sbom"
	"github.com/seebom-labs/bomhort/backend/internal/vex"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func main() {
	log.Println("BOMHort Parsing Worker starting...")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	chClient, err := clickhouse.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to ClickHouse: %v", err)
	}
	defer chClient.Close()

	osvClient := osv.NewClient()

	// Load license policy (permissive/copyleft lists) if available.
	if perm, copy, err := license.LoadPolicy(cfg.LicensePolicyFile); err == nil {
		log.Printf("Loaded license policy from %s (%d permissive, %d copyleft)", cfg.LicensePolicyFile, perm, copy)
	} else {
		log.Printf("Using default license policy (tried %s): %v", cfg.LicensePolicyFile, err)
	}

	// Load license exceptions if available (try config path, then SBOM dir fallback).
	var exceptionsIndex *license.ExceptionIndex
	sbomDirExceptionsPath := cfg.SBOMDir + "/license-exceptions.json"
	if idx, err := license.LoadExceptionsWithFallback(cfg.ExceptionsFile, sbomDirExceptionsPath); err == nil {
		exceptionsIndex = idx
		log.Printf("Loaded license exceptions (%d blanket, %d specific)",
			len(idx.Raw.BlanketExceptions), len(idx.Raw.Exceptions))
	} else {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("Invalid license exceptions configuration: %v", err)
		}
		log.Printf("No license exceptions loaded (tried %s, %s): %v", cfg.ExceptionsFile, sbomDirExceptionsPath, err)
	}

	// Initialize GitHub license resolver for unknown licenses.
	var ghResolver *gh.Resolver
	if !cfg.SkipGitHubResolve {
		ghResolver = gh.NewResolver(cfg.GitHubToken)
		// Preload license cache from ClickHouse.
		if cached, err := chClient.QueryGitHubLicenseCache(context.Background()); err == nil && len(cached) > 0 {
			ghResolver.PreloadCache(cached)
			log.Printf("Preloaded %d GitHub license cache entries", len(cached))
		}
		// Preload repo metadata cache.
		if meta, err := chClient.QueryGitHubRepoMetadata(context.Background()); err == nil && len(meta) > 0 {
			ghResolver.PreloadMetadataCache(meta)
			log.Printf("Preloaded %d GitHub repo metadata entries", len(meta))
		}
		if cfg.GitHubToken != "" {
			log.Println("GitHub license resolver enabled (authenticated, 5000 req/h)")
		} else {
			log.Println("GitHub license resolver enabled (unauthenticated, 60 req/h)")
		}
	} else {
		log.Println("GitHub license resolver disabled (SKIP_GITHUB_RESOLVE=true)")
	}

	// Initialize package-registry license resolvers (npm, NuGet) for licenses
	// that are still unknown after the GitHub pass.
	registryResolvers := newRegistryResolvers(context.Background(), cfg, chClient, ghResolver)

	// Initialize S3 client if S3 buckets are configured.
	var s3c *s3client.Client
	if cfg.HasS3Sources() {
		bucketConfigs := make([]s3client.BucketConfig, len(cfg.S3Buckets))
		for i, b := range cfg.S3Buckets {
			bucketConfigs[i] = s3client.BucketConfig{
				Name:         b.Name,
				Endpoint:     b.Endpoint,
				Region:       b.Region,
				AccessKey:    b.AccessKey,
				SecretKey:    b.SecretKey,
				Prefix:       b.Prefix,
				UsePathStyle: b.UsePathStyle,
				UseSSL:       b.UseSSL,
				SkipScan:     b.SkipScan,
			}
		}
		var err error
		s3c, err = s3client.NewClient(bucketConfigs)
		if err != nil {
			log.Printf("WARNING: Failed to create S3 client: %v (S3 jobs will fail)", err)
		} else {
			log.Printf("S3 client initialized for %d bucket(s): %s", len(cfg.S3Buckets), cfg.S3BucketNames())
		}
	}

	// Tier-2 fidelity capture (#256): blob store for the original SBOM bytes.
	// A nil store means capture is disabled (ORIGINAL_STORE_BACKEND=none or
	// nothing to auto-detect); a misconfigured store is fatal because silently
	// skipping capture would defeat the purpose of the feature.
	originals, err := docstore.FromConfig(cfg, s3c)
	if err != nil {
		log.Fatalf("Failed to initialize original document store: %v", err)
	}
	if originals == nil {
		log.Printf("Original document store disabled (ORIGINAL_STORE_BACKEND=%s) — SBOMs will not be retained byte-for-byte", cfg.OriginalStoreBackend)
	} else {
		if err := docstore.CheckWritable(originals); err != nil {
			log.Fatalf("Original document store is not usable: %v", err)
		}
		log.Printf("Original document store: backend=%s", originals.Backend())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	log.Printf("Worker %s polling for jobs (batch size: %d, skip_osv: %v)...", cfg.WorkerID, cfg.WorkerBatchSize, cfg.SkipOSV)

	// Main polling loop.
	for {
		select {
		case <-ctx.Done():
			log.Println("Worker shutting down.")
			return
		default:
		}

		jobs, err := chClient.ClaimJobs(ctx, cfg.WorkerID, cfg.WorkerBatchSize)
		if err != nil {
			log.Printf("ERROR: Failed to claim jobs: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(jobs) == 0 {
			// No work available, wait before polling again.
			time.Sleep(10 * time.Second)
			continue
		}

		log.Printf("Claimed %d jobs, processing...", len(jobs))

		for _, job := range jobs {
			if err := processJob(ctx, cfg, chClient, osvClient, exceptionsIndex, ghResolver, registryResolvers, s3c, originals, job); err != nil {
				log.Printf("ERROR: Failed to process %s: %v", job.SourceFile, err)
				if failErr := chClient.FailJob(ctx, job, err.Error()); failErr != nil {
					log.Printf("ERROR: Failed to mark job as failed: %v", failErr)
				}
				continue
			}

			if err := chClient.CompleteJob(ctx, job); err != nil {
				log.Printf("ERROR: Failed to mark job as done: %v", err)
			} else {
				log.Printf("Completed: %s", job.SourceFile)
			}
		}
	}
}

func processJob(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, osvClient *osv.Client, exceptions *license.ExceptionIndex, ghResolver *gh.Resolver, registryResolvers []registryResolver, s3c *s3client.Client, originals docstore.Store, job models.IngestionJob) error {
	// Determine how to open the file: S3 URI or local path.
	openFile := func() (io.ReadCloser, error) {
		if strings.HasPrefix(job.SourceFile, "s3://") {
			if s3c == nil {
				return nil, fmt.Errorf("S3 client not configured but job source is %s", job.SourceFile)
			}
			bucket, key, err := s3client.ParseURI(job.SourceFile)
			if err != nil {
				return nil, err
			}
			return s3c.GetObject(ctx, bucket, key)
		}
		// Local file.
		absPath := filepath.Join(cfg.SBOMDir, job.SourceFile)
		return os.Open(absPath)
	}

	// Branch on job type.
	if job.JobType == models.JobTypeVEX {
		return processVEXJob(ctx, chClient, openFile, job)
	}

	return processSBOMJob(ctx, cfg, chClient, osvClient, exceptions, ghResolver, registryResolvers, openFile, originals, job)
}

func processVEXJob(ctx context.Context, chClient *clickhouse.Client, openFile func() (io.ReadCloser, error), job models.IngestionJob) error {
	rc, err := openFile()
	if err != nil {
		return fmt.Errorf("failed to open VEX source %s: %w", job.SourceFile, err)
	}
	defer rc.Close()

	result, err := vex.Parse(rc, job.SourceFile)
	if err != nil {
		return err
	}

	log.Printf("  Parsed VEX %s: %d statements (doc: %s)",
		job.SourceFile, len(result.Statements), result.DocumentID)

	// Idempotency guard with a rescue path: a fully scoped document is
	// skipped, but one that still has unscoped statements is re-processed -
	// the SBOM its product names may have been ingested since. Without
	// this, a VEX file that arrived before its SBOM was skipped as
	// "already ingested" on every later encounter and stayed inert forever.
	replacing := false
	if exists, _ := chClient.VEXDocumentExists(ctx, result.DocumentID); exists {
		unscoped, err := chClient.VEXDocumentUnscopedCount(ctx, result.DocumentID)
		if err != nil {
			return err
		}
		if unscoped == 0 {
			log.Printf("  Skipping VEX %s (already ingested and fully scoped, doc: %s)", job.SourceFile, result.DocumentID)
			return nil
		}
		log.Printf("  Re-processing VEX %s: %d unscoped statement(s) may resolve now (doc: %s)",
			job.SourceFile, unscoped, result.DocumentID)
		replacing = true
	}

	// The VEX parser only sees the document, not the job, so the ownership
	// dimensions have to be stamped on here. This also fixes cluster, which
	// was silently left empty on every VEX row before #138/#57.
	ownershipOf(job).applyVEXStatements(result.Statements)

	// Scope each statement to the SBOM whose product it describes (#350):
	// explicit ?sbom_id= mapping first, then product-@id resolution, global
	// fallback with a warning. A statement scoped to the wrong product would
	// suppress real findings in unrelated projects.
	scopeVEXStatements(ctx, chClient, job, result.Statements)

	// Replace before insert: vex_ids are deterministic, but product_purl is
	// part of the ORDER BY key and changes when a product-wide statement
	// resolves ('*'), so the old unscoped rows would linger otherwise.
	if replacing {
		if err := chClient.DeleteVEXDocument(ctx, result.DocumentID); err != nil {
			return err
		}
	}

	if len(result.Statements) > 0 {
		if err := chClient.InsertVEXStatements(ctx, result.Statements); err != nil {
			return err
		}
	}

	return nil
}

// excludeIndices returns copies of the parallel names/licenses slices without the
// entries at the given indices. With no indices to skip, the inputs are returned as-is.
func excludeIndices(names, licenses []string, skip []uint32) ([]string, []string) {
	if len(skip) == 0 {
		return names, licenses
	}
	skipSet := make(map[uint32]bool, len(skip))
	for _, i := range skip {
		skipSet[i] = true
	}
	outNames := make([]string, 0, len(names))
	outLics := make([]string, 0, len(licenses))
	for i := range names {
		if skipSet[uint32(i)] {
			continue
		}
		outNames = append(outNames, names[i])
		if i < len(licenses) {
			outLics = append(outLics, licenses[i])
		} else {
			outLics = append(outLics, "")
		}
	}
	return outNames, outLics
}

func processSBOMJob(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, osvClient *osv.Client, exceptions *license.ExceptionIndex, ghResolver *gh.Resolver, registryResolvers []registryResolver, openFile func() (io.ReadCloser, error), originals docstore.Store, job models.IngestionJob) error {

	// 1. Read the whole document once. The bytes are needed twice — for the
	// parser and for the Tier-2 original capture (#256) — and sbom.Parse reads
	// everything into memory anyway.
	rc, err := openFile()
	if err != nil {
		return fmt.Errorf("failed to open SBOM source %s: %w", job.SourceFile, err)
	}
	raw, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return fmt.Errorf("failed to read SBOM source %s: %w", job.SourceFile, err)
	}

	result, err := sbom.Parse(bytes.NewReader(raw), job.SourceFile, job.SHA256Hash)
	if err != nil {
		return err
	}

	log.Printf("  Parsed %s: %d packages, %d relationships",
		job.SourceFile,
		len(result.Packages.PackageNames),
		len(result.Packages.RelSourceIndices))

	// 1b. Skip if this SBOM was already fully ingested (idempotency guard).
	if exists, _ := chClient.SBOMExists(ctx, result.SBOM.SBOMID); exists {
		log.Printf("  Skipping %s (already ingested, sbom_id=%s)", job.SourceFile, result.SBOM.SBOMID)
		return nil
	}

	// 1c. Tier-2 fidelity capture (#256): persist the original bytes BEFORE any
	// ClickHouse row is written. If the blob store is unavailable the job fails
	// here and is retried later; had we inserted first, the SBOMExists guard
	// above would skip the retry and the original would be lost for good.
	if originals != nil {
		if err := captureOriginal(ctx, chClient, originals, job, raw, &result.SBOM); err != nil {
			return err
		}
	}

	// 2. Resolve unknown licenses via GitHub API BEFORE inserting into ClickHouse,
	// so that sbom_packages.package_licenses contains the resolved values.
	if ghResolver != nil {
		resolved := 0
		archived := 0
		for i, lic := range result.Packages.PackageLicenses {
			purl := ""
			if i < len(result.Packages.PackagePURLs) {
				purl = result.Packages.PackagePURLs[i]
			}
			if purl == "" {
				continue
			}

			// For unknown licenses, fetch full metadata (license + archived status)
			if lic == "" || lic == "NOASSERTION" || lic == "NONE" {
				if meta := ghResolver.ResolveWithMetadata(ctx, purl); meta != nil {
					if meta.SPDXID != "" {
						result.Packages.PackageLicenses[i] = meta.SPDXID
						resolved++
					}
					if meta.Archived {
						archived++
					}
				}
			}
		}
		if resolved > 0 {
			log.Printf("  Resolved %d unknown licenses via GitHub API", resolved)
		}
		if archived > 0 {
			log.Printf("  ⚠️  Found %d packages using ARCHIVED GitHub repos", archived)
		}
		// Persist caches to ClickHouse.
		if entries := ghResolver.CacheEntries(); len(entries) > 0 {
			_ = chClient.InsertGitHubLicenseCache(ctx, entries)
		}
		if metaEntries := ghResolver.MetadataCacheEntries(); len(metaEntries) > 0 {
			_ = chClient.InsertGitHubRepoMetadata(ctx, metaEntries)
		}
	}

	// 2b. Resolve remaining unknown licenses via package registries (npm, NuGet).
	resolveViaRegistries(ctx, chClient, registryResolvers, result.Packages.PackagePURLs, result.Packages.PackageLicenses)

	// 3. Insert SBOM metadata. Every row written from here on carries the
	// job's ownership dimensions (#131 cluster, #138 namespace, #57 project).
	own := ownershipOf(job)
	own.applySBOM(&result.SBOM)
	applySourceOverride(&result.SBOM, job)
	if err := chClient.InsertSBOM(ctx, &result.SBOM); err != nil {
		return err
	}

	// 4. Insert package arrays (with resolved licenses).
	own.applyPackages(&result.Packages)
	if err := chClient.InsertSBOMPackages(ctx, &result.Packages); err != nil {
		return err
	}

	// 5. OSV batch query for vulnerabilities (skippable for fast ingestion).
	if cfg.SkipOSV {
		log.Printf("  SKIP_OSV=true, skipping vulnerability scan for %s (%d PURLs)", job.SourceFile, len(result.Packages.PackagePURLs))
	} else {
		// Filter out empty PURLs first.
		var purls []string
		purlToIndex := make(map[string]int) // track which PURL maps to which query index
		for _, purl := range result.Packages.PackagePURLs {
			if purl != "" {
				purlToIndex[purl] = len(purls)
				purls = append(purls, purl)
			}
		}

		var vulns []models.Vulnerability
		if len(purls) > 0 {
			// Collect vuln IDs from batch queries, then hydrate with full details.
			type vulnPURL struct {
				id   string
				purl string
			}
			var discovered []vulnPURL

			// Chunk PURLs into batches of 1000 (OSV API limit).
			const chunkSize = 1000
			for i := 0; i < len(purls); i += chunkSize {
				end := i + chunkSize
				if end > len(purls) {
					end = len(purls)
				}
				chunk := purls[i:end]

				osvResp, err := osvClient.QueryBatch(ctx, chunk)
				if err != nil {
					log.Printf("  WARNING: OSV query failed for chunk %d-%d: %v", i, end, err)
					continue
				}

				for j, qr := range osvResp.Results {
					if len(qr.Vulns) == 0 {
						continue
					}
					purl := chunk[j]
					for _, v := range qr.Vulns {
						discovered = append(discovered, vulnPURL{id: v.ID, purl: purl})
					}
				}
			}

			if len(discovered) > 0 {
				// Collect unique vuln IDs and hydrate with full details.
				uniqueIDs := make([]string, 0)
				seen := make(map[string]struct{})
				for _, d := range discovered {
					if _, ok := seen[d.id]; !ok {
						seen[d.id] = struct{}{}
						uniqueIDs = append(uniqueIDs, d.id)
					}
				}

				hydrated, err := osvClient.HydrateVulns(ctx, uniqueIDs)
				if err != nil {
					log.Printf("  WARNING: Hydration failed: %v", err)
				}

				// Build vulnerability models using hydrated data.
				for _, d := range discovered {
					var entry osv.VulnEntry
					if h, ok := hydrated[d.id]; ok {
						entry = *h
					} else {
						// Fallback: minimal entry if hydration failed for this ID.
						entry = osv.VulnEntry{ID: d.id}
					}

					severity := osvutil.ClassifySeverity(entry)
					fixedVersion := osvutil.ExtractFixedVersion(entry)
					affectedVersions := osvutil.ExtractAffectedVersions(entry)
					rawJSON, _ := json.Marshal(entry)

					v := models.Vulnerability{
						DiscoveredAt:     time.Now(),
						SBOMID:           result.SBOM.SBOMID,
						SourceFile:       job.SourceFile,
						PURL:             d.purl,
						VulnID:           entry.ID,
						Severity:         severity,
						Summary:          entry.Summary,
						Aliases:          entry.Aliases,
						AffectedVersions: affectedVersions,
						FixedVersion:     fixedVersion,
						OSVJSON:          string(rawJSON),
					}
					own.applyVulnerability(&v)
					vulns = append(vulns, v)
				}
			}

			if len(vulns) > 0 {
				log.Printf("  Found %d vulnerabilities in %s", len(vulns), job.SourceFile)
				if err := chClient.InsertVulnerabilities(ctx, vulns); err != nil {
					return err
				}
			}
		}
	}

	// 6. License compliance check (uses the already-resolved licenses).
	// The described root (the product itself) is not a dependency and must not
	// show up in the license breakdown, e.g. as a NOASSERTION finding.
	licNames, licLicenses := excludeIndices(result.Packages.PackageNames, result.Packages.PackageLicenses, result.Packages.RootIndices)
	licResults := license.CheckWithExceptions(licNames, licLicenses, exceptions, result.SBOM.DocumentName)
	if len(licResults) > 0 {
		licModels := make([]models.LicenseCompliance, len(licResults))
		for i, lr := range licResults {
			nonCompliant := lr.NonCompliantPackages
			if nonCompliant == nil {
				nonCompliant = []string{}
			}
			exempted := lr.ExemptedPackages
			if exempted == nil {
				exempted = []string{}
			}
			licModels[i] = models.LicenseCompliance{
				CheckedAt:            time.Now(),
				SBOMID:               result.SBOM.SBOMID,
				SourceFile:           job.SourceFile,
				LicenseID:            lr.LicenseID,
				Category:             string(lr.Category),
				PackageCount:         lr.PackageCount,
				NonCompliantPackages: nonCompliant,
				ExemptedPackages:     exempted,
				ExemptionReason:      lr.ExemptionReason,
			}
			own.applyLicenseCompliance(&licModels[i])
		}
		if err := chClient.InsertLicenseCompliance(ctx, licModels); err != nil {
			return err
		}
	}

	// 7. Rescue VEX statements that arrived before this SBOM (#350): their
	// product @id failed to resolve at their own ingest and they have been
	// suppressing nothing since. Now that a new resolution target exists,
	// retry them. Best effort by design - the SBOM is fully ingested at
	// this point and VEX bookkeeping must not fail the job.
	rescueUnscopedVEX(ctx, chClient, job.SourceFile)

	return nil
}

// captureOriginal stores the raw document bytes in the blob store and records
// the reference in document_store. The sha256 is computed here rather than
// taken from the job because S3-discovered jobs carry the bucket ETag, which
// is not a sha256.
//
// Blobs are gzip-compressed by the store; sha256/size describe the original
// bytes, StoredSizeBytes what the object occupies on disk.
func captureOriginal(ctx context.Context, chClient *clickhouse.Client, store docstore.Store, job models.IngestionJob, raw []byte, meta *models.SBOM) error {
	// Remember a previous capture (re-ingest of the same sbom_id) so its blob
	// can be removed once the new one is safely written and recorded — the
	// ReplacingMergeTree row is superseded, but the object would otherwise
	// linger as an orphan and silently eat storage.
	var previous *models.StoredDocument
	if prev, err := chClient.QueryStoredDocument(ctx, meta.SBOMID.String()); err == nil {
		previous = prev
	} else if !errors.Is(err, clickhouse.ErrDocumentNotStored) {
		log.Printf("  WARNING: previous-original lookup for %s failed (orphan cleanup skipped): %v", meta.SBOMID, err)
	}

	res, err := store.Put(ctx, docstore.Key(meta.SBOMID.String(), job.SourceFile), raw)
	if err != nil {
		return fmt.Errorf("failed to store original for %s: %w", job.SourceFile, err)
	}

	doc := &models.StoredDocument{
		StoredAt:        time.Now(),
		SBOMID:          meta.SBOMID,
		SourceFile:      job.SourceFile,
		StorageBackend:  store.Backend(),
		StorageRef:      res.Ref,
		SHA256Hash:      docstore.SHA256Hex(raw),
		SizeBytes:       uint64(len(raw)),
		ContentType:     "application/json",
		ContentEncoding: res.Encoding,
		StoredSizeBytes: res.StoredBytes,
	}
	ownershipOf(job).applyStoredDocument(doc)

	if err := chClient.InsertStoredDocument(ctx, doc); err != nil {
		return fmt.Errorf("failed to record original for %s: %w", job.SourceFile, err)
	}
	log.Printf("  Stored original (%d bytes → %d stored, %s, %s) at %s", len(raw), res.StoredBytes, res.Encoding, store.Backend(), res.Ref)

	// Best effort: the new capture is durable, so losing the old blob is the
	// desired outcome and a failure here must not fail the job.
	if previous != nil && previous.StorageRef != res.Ref && previous.StorageBackend == store.Backend() {
		if err := store.Delete(ctx, previous.StorageRef); err != nil {
			log.Printf("  WARNING: could not remove superseded original %s: %v", previous.StorageRef, err)
		} else {
			log.Printf("  Removed superseded original %s", previous.StorageRef)
		}
	}
	return nil
}
