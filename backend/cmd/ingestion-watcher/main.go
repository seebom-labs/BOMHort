package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/ingestpath"
	"github.com/seebom-labs/bomhort/backend/internal/repo"
	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
	tagpkg "github.com/seebom-labs/bomhort/backend/internal/tags"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const enqueueBatchSize = 500

// ownership carries the three orthogonal dimensions (#131 cluster, #138
// namespace, #57 project) an ingestion source assigns to its objects,
// together with everything needed to derive the per-object part of them.
type ownership struct {
	// cluster/namespace/project are the explicitly configured values
	// (per-bucket, falling back to the instance-wide defaults). Empty
	// fields are the ones the path layout is allowed to fill in.
	cluster   string
	namespace string
	project   string
	// prefix is the bucket's configured key prefix. The layout is defined
	// relative to the ingestion root, so the prefix must be stripped from
	// an object key before matching -- otherwise a bucket configured with
	// prefix "k3s-io/" would read that as the cluster segment.
	prefix string
	layout ingestpath.Layout
	// tags are the bucket's configured grouping labels (global TAGS merged
	// with the bucket's own). Every object in the bucket carries them; a
	// layout with "tag" segments adds per-object labels on top (#398).
	tags []string
	// parent is the bucket's explicit parent (bucket "parent", else PARENT);
	// a "parent" layout segment fills it when both are empty.
	parent string
}

// resolve returns the ownership for one object key, applying path
// derivation on top of the configured values. Dimensions are either/or
// (explicit config wins); tags are additive, so path-derived labels join the
// configured ones rather than replacing them.
func (o ownership) resolve(key string) (cluster, namespace, project, parent string, tags []string) {
	cluster, namespace, project, parent, tags = o.cluster, o.namespace, o.project, o.parent, o.tags
	if !o.layout.Enabled() {
		return
	}
	derived := o.layout.Derive(stripPrefix(key, o.prefix))
	ingestpath.Apply(derived, &cluster, &namespace, &project, &parent)
	if len(derived.Tags) > 0 {
		tags = tagpkg.Merge(o.tags, derived.Tags)
	}
	return
}

// stripPrefix removes a bucket's configured key prefix from an object key,
// tolerating a prefix written with or without a trailing slash. A key that
// does not start with the prefix is returned unchanged rather than mangled.
func stripPrefix(key, prefix string) string {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return key
	}
	return strings.TrimPrefix(strings.TrimPrefix(key, prefix), "/")
}

// firstNonEmpty returns the first non-empty argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func main() {
	log.Println("BOMHort Ingestion Watcher starting...")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	chClient, err := clickhouse.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to ClickHouse: %v", err)
	}
	defer chClient.Close()

	ctx := context.Background()

	var totalEnqueued int
	sbomCount := 0 // tracks SBOMs seen (for SBOM_LIMIT enforcement)

	// One query for the whole run instead of one per file (#487). A job
	// whose latest status is 'failed' is not in the set, so its file is
	// enqueued again (#482).
	known, err := chClient.KnownHashes(ctx)
	if err != nil {
		log.Fatalf("Failed to load known hashes: %v", err)
	}
	log.Printf("Loaded %d known content hashes", len(known))

	// ── Source 1: Local filesystem ─────────────────────────────────────
	if cfg.SBOMDir != "" {
		if info, err := os.Stat(cfg.SBOMDir); err == nil && info.IsDir() {
			localEnqueued, _ := ingestLocalFiles(ctx, cfg, chClient, known, &sbomCount)
			totalEnqueued += localEnqueued
		} else {
			log.Printf("Local: SBOM directory %s does not exist, skipping local scan", cfg.SBOMDir)
		}
	}

	// ── Source 2: S3 buckets ───────────────────────────────────────────
	if cfg.HasS3Sources() {
		s3Enqueued := ingestS3Buckets(ctx, cfg, chClient, known, &sbomCount)
		totalEnqueued += s3Enqueued
	}

	if totalEnqueued == 0 {
		log.Println("No new files to ingest. Exiting.")
	} else {
		log.Printf("Successfully enqueued %d total jobs. Watcher done.", totalEnqueued)
	}
}

// ingestLocalFiles scans the local SBOM directory and enqueues new files.
// Returns (enqueued count, sbom files seen).
func ingestLocalFiles(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, known map[string]struct{}, sbomCount *int) (int, int) {
	scanner := repo.NewScannerWithIgnorePrefix(cfg.SBOMDir, cfg.IgnorePrefix)
	files, err := scanner.Scan()
	if err != nil {
		log.Printf("WARNING: Failed to scan local SBOM directory %s: %v", cfg.SBOMDir, err)
		return 0, 0
	}

	layout := cfg.IngestLayout()
	if layout.Enabled() {
		log.Printf("Local: deriving ownership from path layout %q (relative to %s)", layout.String(), cfg.SBOMDir)
	}

	localSBOMs := 0
	localVEX := 0
	for _, f := range files {
		if f.FileType == "vex" {
			localVEX++
		} else {
			localSBOMs++
		}
	}
	log.Printf("Local: found %d SBOM files and %d VEX files in %s", localSBOMs, localVEX, cfg.SBOMDir)

	// Stream-process files in batches for efficient enqueuing.
	var batch []models.IngestionJob
	enqueued := 0
	seen := map[string]struct{}{} // hashes enqueued by this scan, for the duplicate log line

	for _, f := range files {
		// Apply SBOM_LIMIT (VEX files are never limited).
		if f.FileType != "vex" {
			if cfg.SBOMLimit > 0 && *sbomCount >= cfg.SBOMLimit {
				continue
			}
			*sbomCount++
		}

		if _, exists := known[f.SHA256Hash]; exists {
			if _, thisScan := seen[f.SHA256Hash]; thisScan {
				log.Printf("Local: skipping %s, same content as an earlier file in this scan (first path's ownership wins)", f.RelPath)
			}
			continue
		}
		known[f.SHA256Hash], seen[f.SHA256Hash] = struct{}{}, struct{}{}

		jobType := models.JobTypeSBOM
		if f.FileType == "vex" {
			jobType = models.JobTypeVEX
		}

		// Start from the instance-wide defaults, then let the path fill in
		// whatever they left unset. RelPath is already relative to SBOM_DIR,
		// which is exactly the root the layout is defined against.
		cluster, namespace, project, parent := cfg.ClusterName, cfg.Namespace, cfg.Project, cfg.Parent
		derived := layout.Derive(f.RelPath)
		ingestpath.Apply(derived, &cluster, &namespace, &project, &parent)
		fileTags := cfg.Tags
		if len(derived.Tags) > 0 {
			fileTags = tagpkg.Merge(cfg.Tags, derived.Tags)
		}

		batch = append(batch, models.IngestionJob{
			CreatedAt:  time.Now(),
			JobID:      uuid.New(),
			SourceFile: f.RelPath,
			SHA256Hash: f.SHA256Hash,
			Status:     models.JobStatusPending,
			JobType:    jobType,
			Cluster:    cluster,
			Namespace:  namespace,
			Project:    project,
			Tags:       fileTags,
			Parent:     parent,
		})

		// Flush batch when it reaches the threshold.
		if len(batch) >= enqueueBatchSize {
			if err := chClient.EnqueueJobs(ctx, batch); err != nil {
				log.Printf("ERROR: Failed to enqueue local batch: %v", err)
			} else {
				enqueued += len(batch)
				log.Printf("Local: enqueued batch of %d jobs (%d total)", len(batch), enqueued)
			}
			batch = batch[:0]
		}
	}

	// Flush remaining.
	if len(batch) > 0 {
		if err := chClient.EnqueueJobs(ctx, batch); err != nil {
			log.Printf("ERROR: Failed to enqueue final local batch: %v", err)
		} else {
			enqueued += len(batch)
		}
	}

	if enqueued > 0 {
		log.Printf("Local: enqueued %d new jobs from %s", enqueued, cfg.SBOMDir)
	}

	return enqueued, localSBOMs
}

// ingestS3Buckets streams objects from all configured S3 buckets and enqueues new files.
func ingestS3Buckets(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, known map[string]struct{}, sbomCount *int) int {
	// Convert config bucket types to s3 package types.
	bucketConfigs := make([]s3client.BucketConfig, len(cfg.S3Buckets))
	// Build the bucket->ownership mapping: per-bucket values override the
	// instance-wide defaults. Whatever is still empty afterwards is left
	// for the path layout to fill in per object.
	bucketOwner := make(map[string]ownership, len(cfg.S3Buckets))
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

		own := ownership{
			cluster:   firstNonEmpty(b.Cluster, cfg.ClusterName),
			namespace: firstNonEmpty(b.Namespace, cfg.Namespace),
			project:   firstNonEmpty(b.Project, cfg.Project),
			parent:    firstNonEmpty(strings.TrimSpace(b.Parent), cfg.Parent),
			prefix:    b.Prefix,
			layout:    cfg.BucketIngestLayout(b),
			tags:      cfg.BucketTags(b),
		}
		if own.layout.Enabled() {
			log.Printf("S3: bucket %q derives ownership from path layout %q", b.Name, own.layout.String())
		}
		bucketOwner[b.Name] = own
	}

	s3c, err := s3client.NewClient(bucketConfigs)
	if err != nil {
		log.Printf("ERROR: Failed to create S3 client: %v", err)
		return 0
	}

	log.Printf("S3: scanning %d bucket(s): %s", len(cfg.S3Buckets), cfg.S3BucketNames())

	var batch []models.IngestionJob
	enqueued := 0
	seen := map[string]struct{}{}
	skipped := 0
	errors := 0

	objCh := s3c.ListObjects(ctx)
	for result := range objCh {
		if result.Err != nil {
			log.Printf("WARNING: %v", result.Err)
			errors++
			continue
		}

		obj := result.Object

		// Apply SBOM_LIMIT (VEX files are never limited).
		if obj.FileType != "vex" {
			if cfg.SBOMLimit > 0 && *sbomCount >= cfg.SBOMLimit {
				skipped++
				continue
			}
			*sbomCount++
		}

		// Dedup on the S3 ETag (changes when content changes).
		if _, exists := known[obj.ETag]; exists {
			if _, thisScan := seen[obj.ETag]; thisScan {
				log.Printf("S3: skipping %s, same content as an earlier object in this scan (first object's ownership wins)", obj.URI())
			}
			continue
		}
		known[obj.ETag], seen[obj.ETag] = struct{}{}, struct{}{}

		jobType := models.JobTypeSBOM
		if obj.FileType == "vex" {
			jobType = models.JobTypeVEX
		}

		cluster, namespace, project, parent, objTags := bucketOwner[obj.Bucket].resolve(obj.Key)

		// SourceFile stores the s3:// URI so the worker knows where to fetch.
		batch = append(batch, models.IngestionJob{
			CreatedAt:  time.Now(),
			JobID:      uuid.New(),
			SourceFile: obj.URI(),
			SHA256Hash: obj.ETag, // Use ETag for dedup (no download needed during listing)
			Status:     models.JobStatusPending,
			JobType:    jobType,
			Cluster:    cluster,
			Namespace:  namespace,
			Project:    project,
			Tags:       objTags,
			Parent:     parent,
		})

		// Flush batch.
		if len(batch) >= enqueueBatchSize {
			if err := chClient.EnqueueJobs(ctx, batch); err != nil {
				log.Printf("ERROR: Failed to enqueue S3 batch: %v", err)
			} else {
				enqueued += len(batch)
				log.Printf("S3: enqueued batch of %d jobs (%d total)", len(batch), enqueued)
			}
			batch = batch[:0]
		}
	}

	// Flush remaining.
	if len(batch) > 0 {
		if err := chClient.EnqueueJobs(ctx, batch); err != nil {
			log.Printf("ERROR: Failed to enqueue final S3 batch: %v", err)
		} else {
			enqueued += len(batch)
		}
	}

	if skipped > 0 {
		log.Printf("S3: skipped %d SBOMs due to SBOM_LIMIT=%d", skipped, cfg.SBOMLimit)
	}
	if errors > 0 {
		log.Printf("S3: encountered %d errors during listing", errors)
	}
	if enqueued > 0 {
		log.Printf("S3: enqueued %d new jobs", enqueued)
	}

	return enqueued
}

// isS3URI returns true if the source file path is an S3 URI.
func isS3URI(sourceFile string) bool {
	return strings.HasPrefix(sourceFile, "s3://")
}
