package main

import (
	"errors"
	"fmt"
	"path/filepath"
)

// safeLocalSBOMPath validates and resolves a relative sourceFile path within baseDir.
// It rejects empty baseDir and paths attempting directory traversal or escaping baseDir.
func safeLocalSBOMPath(baseDir, sourceFile string) (string, error) {
	if baseDir == "" {
		return "", errors.New("local storage not configured")
	}
	if !filepath.IsLocal(sourceFile) || filepath.Clean(sourceFile) == "." {
		return "", fmt.Errorf("invalid source file path: %q", sourceFile)
	}
	return filepath.Join(baseDir, sourceFile), nil
}
