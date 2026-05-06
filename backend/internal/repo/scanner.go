package repo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// FileInfo holds metadata about a discovered file.
type FileInfo struct {
	// RelPath is the path relative to the root directory (local files)
	// or the S3 object key (S3 files).
	RelPath    string
	AbsPath    string
	SHA256Hash string
	FileType   string // "sbom" or "vex"
	SourceType string // "local" or "s3" (empty defaults to "local")
	SourceURI  string // For S3: "s3://bucket/key". Empty for local files.
}

// Scanner walks a directory to discover SPDX JSON files and compute their hashes.
type Scanner struct {
	rootDir string
}

// NewScanner creates a new Scanner for the given root directory.
func NewScanner(rootDir string) *Scanner {
	return &Scanner{rootDir: rootDir}
}

// Scan walks the root directory and returns all .spdx.json files with their hashes.
func (s *Scanner) Scan() ([]FileInfo, error) {
	var files []FileInfo

	err := filepath.Walk(s.rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// If the root directory itself is unreadable, fail immediately.
			if path == s.rootDir {
				return fmt.Errorf("error walking path %s: %w", path, err)
			}
			// Permission denied or unreadable child entry (e.g. lost+found on ext4).
			// Skip the directory/file and continue scanning.
			log.Printf("Skipping unreadable path %s: %v", path, err)
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			// Skip hidden directories (.git, .cache, etc.) and lost+found.
			name := info.Name()
			if name == "lost+found" || name == ".git" || (strings.HasPrefix(name, ".") && name != ".") {
				return filepath.SkipDir
			}
			return nil
		}

		// Classify file type: VEX or SBOM.
		name := strings.ToLower(info.Name())
		fileType := ""
		switch {
		case strings.HasSuffix(name, ".openvex.json"), strings.HasSuffix(name, ".vex.json"):
			fileType = "vex"
		case strings.HasSuffix(name, ".spdx.json"), strings.HasSuffix(name, ".cdx.json"), strings.HasSuffix(name, ".json"):
			fileType = "sbom"
		default:
			return nil
		}

		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("failed to hash file %s: %w", path, err)
		}

		relPath, err := filepath.Rel(s.rootDir, path)
		if err != nil {
			return fmt.Errorf("failed to compute relative path: %w", err)
		}

		files = append(files, FileInfo{
			RelPath:    relPath,
			AbsPath:    path,
			SHA256Hash: hash,
			FileType:   fileType,
		})

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan directory %s: %w", s.rootDir, err)
	}

	return files, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
