package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestDocumentedScannerExample(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("scanner example requires %s: %v", tool, err)
		}
	}
	raw, err := os.ReadFile(scanningClusterDoc)
	if err != nil {
		t.Fatal(err)
	}
	section := strings.SplitN(string(raw), "### A minimal scanner", 2)
	if len(section) != 2 {
		t.Fatal("scanner example section not found")
	}
	fence := strings.SplitN(section[1], "```bash\n", 2)
	if len(fence) != 2 {
		t.Fatal("scanner example script not found")
	}
	script, _, ok := strings.Cut(fence[1], "\n```")
	if !ok {
		t.Fatal("scanner example script is not closed")
	}

	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	running := func(id string) map[string]any {
		return map[string]any{"imageID": id, "state": map[string]any{"running": map[string]any{}}}
	}
	terminated := func(id string) map[string]any {
		return map[string]any{"imageID": id, "state": map[string]any{"terminated": map[string]any{"exitCode": 0}}}
	}
	pod := func(namespace, name, project string, containers, init []map[string]any) map[string]any {
		return map[string]any{
			"metadata": map[string]any{
				"namespace": namespace, "name": name,
				"labels":          map[string]string{"app.kubernetes.io/name": project},
				"ownerReferences": []map[string]string{{"kind": "ReplicaSet", "name": name + "-rs"}},
			},
			"status": map[string]any{"containerStatuses": containers, "initContainerStatuses": init},
		}
	}
	valid := pod("one", "first", "shop", []map[string]any{
		running("docker-pullable://ghcr.io/acme/app@sha256:" + a),
		{"imageID": "", "state": map[string]any{"waiting": map[string]any{}}},
		terminated("ghcr.io/acme/stopped@sha256:" + b),
	}, nil)
	tests := []struct {
		name        string
		pods        []map[string]any
		namespace   string
		wantError   string
		wantUploads int
		wantSyft    int
		httpStatus  int
	}{
		{
			name: "deduplicates by digest and ownership",
			pods: []map[string]any{
				valid,
				pod("one", "second", "shop", []map[string]any{running("ghcr.io/alias/app@sha256:" + a)}, nil),
				pod("two", "third", "shop", []map[string]any{running("ghcr.io/acme/app@sha256:" + a)}, nil),
				pod("one", "fourth", "batch", nil, []map[string]any{terminated("ghcr.io/acme/init@sha256:" + b)}),
			},
			namespace: "https://generator.test/doc", wantUploads: 3, wantSyft: 2,
		},
		{
			name: "missing project fails before uploads",
			pods: []map[string]any{
				valid, pod("one", "unlabelled", "", []map[string]any{running("ghcr.io/acme/app@sha256:" + a)}, nil),
			},
			namespace: "https://generator.test/doc", wantError: "missing project label",
		},
		{
			name: "local image ID fails before uploads",
			pods: []map[string]any{
				valid, pod("one", "local-id", "shop", []map[string]any{running("sha256:" + a)}, nil),
			},
			namespace: "https://generator.test/doc", wantError: "unsupported imageID",
		},
		{
			name: "missing SPDX namespace fails before uploads",
			pods: []map[string]any{valid}, wantError: "generated SPDX has no documentNamespace", wantSyft: 1,
		},
		{
			name: "redirect is not accepted as a successful upload",
			pods: []map[string]any{valid}, namespace: "https://generator.test/doc",
			httpStatus: http.StatusMovedPermanently, wantError: "unexpected HTTP status 301", wantUploads: 1, wantSyft: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			pods, err := json.Marshal(map[string]any{"items": tc.pods})
			if err != nil {
				t.Fatal(err)
			}
			podsFile, syftLog := filepath.Join(dir, "pods.json"), filepath.Join(dir, "syft.log")
			for path, content := range map[string]string{
				podsFile: string(pods),
				filepath.Join(bin, "kubectl"): "#!/bin/sh\n" +
					"exec cat \"$SCANNER_PODS\"\n",
				filepath.Join(bin, "syft"): "#!/bin/sh\n" +
					"printf '%s\\n' \"$1\" >> \"$SCANNER_SYFT_LOG\"\n" +
					"printf '{\"spdxVersion\":\"SPDX-2.3\",\"documentNamespace\":\"%s\"}' \"$SCANNER_SYFT_NAMESPACE\"\n",
			} {
				if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
					t.Fatal(err)
				}
			}

			type upload struct {
				cluster, namespace, project, origin, image, filename, apiKey, documentNamespace string
			}
			var mu sync.Mutex
			var uploads []upload
			store := &fakeUploadStore{}
			handler := authMiddleware(true, false, "", []string{"test-key"}, localUploadHandler(testUploadConfig(t), store))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var doc struct {
					Namespace string `json:"documentNamespace"`
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || r.Method != http.MethodPost || r.URL.Path != "/api/v1/sboms/upload" || json.Unmarshal(body, &doc) != nil {
					http.Error(w, "invalid upload", http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				q := r.URL.Query()
				mu.Lock()
				defer mu.Unlock()
				uploads = append(uploads, upload{q.Get("cluster"), q.Get("namespace"), q.Get("project"),
					q.Get("origin"), q.Get("image"), r.Header.Get("X-Filename"), r.Header.Get("X-API-Key"), doc.Namespace})
				if tc.httpStatus != 0 {
					w.WriteHeader(tc.httpStatus)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"BOMHORT_URL="+server.URL, "BOMHORT_API_KEY=test-key", "CLUSTER_NAME=prod/eu + blue",
				"PROJECT_LABEL=app.kubernetes.io/name", "SCANNER_PODS="+podsFile,
				"SCANNER_SYFT_LOG="+syftLog, "SCANNER_SYFT_NAMESPACE="+tc.namespace,
				"TMPDIR="+dir, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
			)
			output, err := cmd.CombinedOutput()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(string(output), tc.wantError) {
					t.Fatalf("scanner error = %v, output = %s; want %q", err, output, tc.wantError)
				}
			} else if err != nil {
				t.Fatalf("scanner failed: %v\n%s", err, output)
			}

			mu.Lock()
			gotUploads := append([]upload(nil), uploads...)
			gotJobs := append([]models.IngestionJob(nil), store.enqueuedJobs...)
			mu.Unlock()
			wantJobs := tc.wantUploads
			if tc.httpStatus != 0 {
				wantJobs = 0
			}
			if len(gotUploads) != tc.wantUploads || len(gotJobs) != wantJobs {
				t.Fatalf("uploads = %d, queued jobs = %d, want %d uploads and %d jobs: %s",
					len(gotUploads), len(gotJobs), tc.wantUploads, wantJobs, output)
			}
			if len(gotJobs) > 0 {
				want := map[string]string{"one/shop": a, "two/shop": a, "one/batch": b}
				namespaces := map[string]bool{}
				hashes := map[string]bool{}
				for i, u := range gotUploads {
					key := u.namespace + "/" + u.project
					digest, exists := want[key]
					if !exists || !strings.HasSuffix(u.image, "@sha256:"+digest) {
						t.Errorf("unexpected upload %s: %s", key, u.image)
					}
					delete(want, key)
					if u.cluster != "prod/eu + blue" || u.origin != "cluster-scan" ||
						u.apiKey != "test-key" || u.filename != digest+".spdx.json" {
						t.Errorf("incorrect upload parameters: %+v", u)
					}
					if !strings.HasPrefix(u.documentNamespace, tc.namespace+"/prod%2Feu%20%2B%20blue/") || namespaces[u.documentNamespace] {
						t.Errorf("invalid or duplicate document namespace %q", u.documentNamespace)
					}
					namespaces[u.documentNamespace] = true
					job := gotJobs[i]
					if job.Cluster != u.cluster || job.Namespace != u.namespace || job.Project != u.project ||
						job.Origin != u.origin || job.ImageDigest != "sha256:"+digest || hashes[job.SHA256Hash] {
						t.Errorf("incorrect or duplicate queued job: %+v", job)
					}
					hashes[job.SHA256Hash] = true
				}
				if len(want) != 0 {
					t.Errorf("missing ownership uploads: %v", want)
				}
			}
			log, err := os.ReadFile(syftLog)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if got := len(strings.Fields(string(log))); got != tc.wantSyft {
				t.Errorf("syft runs = %d, want %d: %s", got, tc.wantSyft, log)
			}
		})
	}
}
