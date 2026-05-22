package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/seebom/backend/internal/clickhouse"
	"github.com/seebom-labs/seebom/backend/internal/config"
	"github.com/seebom-labs/seebom/backend/internal/repo"
	s3client "github.com/seebom-labs/seebom/backend/internal/s3"
	"github.com/seebom-labs/seebom/backend/pkg/models"
)

const enqueueBatchSize = 500

func main() {
	log.Println("SeeBOM Ingestion Watcher starting...")

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

	// ── Source 1: Local filesystem ─────────────────────────────────────
	if cfg.SBOMDir != "" {
		if info, err := os.Stat(cfg.SBOMDir); err == nil && info.IsDir() {
			localEnqueued, _ := ingestLocalFiles(ctx, cfg, chClient, &sbomCount)
			totalEnqueued += localEnqueued
		} else {
			log.Printf("Local: SBOM directory %s does not exist, skipping local scan", cfg.SBOMDir)
		}
	}

	// ── Source 2: S3 buckets ───────────────────────────────────────────
	if cfg.HasS3Sources() {
		s3Enqueued := ingestS3Buckets(ctx, cfg, chClient, &sbomCount)
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
func ingestLocalFiles(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, sbomCount *int) (int, int) {
	scanner := repo.NewScanner(cfg.SBOMDir)
	files, err := scanner.Scan()
	if err != nil {
		log.Printf("WARNING: Failed to scan local SBOM directory %s: %v", cfg.SBOMDir, err)
		return 0, 0
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

	for _, f := range files {
		// Apply SBOM_LIMIT (VEX files are never limited).
		if f.FileType != "vex" {
			if cfg.SBOMLimit > 0 && *sbomCount >= cfg.SBOMLimit {
				continue
			}
			*sbomCount++
		}

		// Dedup against ClickHouse.
		exists, err := chClient.HashExists(ctx, f.SHA256Hash)
		if err != nil {
			log.Printf("WARNING: Failed to check hash for %s: %v", f.RelPath, err)
			continue
		}
		if exists {
			continue
		}

		jobType := models.JobTypeSBOM
		if f.FileType == "vex" {
			jobType = models.JobTypeVEX
		}

		batch = append(batch, models.IngestionJob{
			CreatedAt:  time.Now(),
			JobID:      uuid.New(),
			SourceFile: f.RelPath,
			SHA256Hash: f.SHA256Hash,
			Status:     models.JobStatusPending,
			JobType:    jobType,
			Cluster:    cfg.ClusterName,
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
func ingestS3Buckets(ctx context.Context, cfg *config.Config, chClient *clickhouse.Client, sbomCount *int) int {
	// Convert config bucket types to s3 package types.
	bucketConfigs := make([]s3client.BucketConfig, len(cfg.S3Buckets))
	// Build bucket→cluster mapping: per-bucket cluster overrides global ClusterName.
	bucketCluster := make(map[string]string, len(cfg.S3Buckets))
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
		}
		if b.Cluster != "" {
			bucketCluster[b.Name] = b.Cluster
		} else {
			bucketCluster[b.Name] = cfg.ClusterName
		}
	}

	s3c, err := s3client.NewClient(bucketConfigs)
	if err != nil {
		log.Printf("ERROR: Failed to create S3 client: %v", err)
		return 0
	}

	log.Printf("S3: scanning %d bucket(s): %s", len(cfg.S3Buckets), cfg.S3BucketNames())

	var batch []models.IngestionJob
	enqueued := 0
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

		// Dedup against ClickHouse using S3 ETag (changes when content changes).
		exists, err := chClient.HashExists(ctx, obj.ETag)
		if err != nil {
			log.Printf("WARNING: Failed to check hash for %s: %v", obj.URI(), err)
			continue
		}
		if exists {
			continue
		}

		jobType := models.JobTypeSBOM
		if obj.FileType == "vex" {
			jobType = models.JobTypeVEX
		}

		// SourceFile stores the s3:// URI so the worker knows where to fetch.
		batch = append(batch, models.IngestionJob{
			CreatedAt:  time.Now(),
			JobID:      uuid.New(),
			SourceFile: obj.URI(),
			SHA256Hash: obj.ETag, // Use ETag for dedup (no download needed during listing)
			Status:     models.JobStatusPending,
			JobType:    jobType,
			Cluster:    bucketCluster[obj.Bucket],
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
