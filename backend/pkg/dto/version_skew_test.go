package dto

import (
	"encoding/json"
	"testing"
)

func TestVersionSkewResponseJSON(t *testing.T) {
	resp := VersionSkewResponse{
		TotalSkewedPackages: 42,
		Page:                1,
		PageSize:            50,
		Items: []VersionSkewItem{
			{
				PackageName:     "golang.org/x/net",
				PURL:            "pkg:golang/golang.org/x/net@v0.17.0",
				VersionCount:    3,
				ProjectCount:    5,
				IsDirectInCount: 2,
				Versions: []VersionSkewDetail{
					{Version: "v0.17.0", ProjectCount: 3, Projects: []string{"etcd-io/raft", "kubernetes/kubernetes", "containerd/containerd"}},
					{Version: "v0.21.0", ProjectCount: 2, Projects: []string{"prometheus/prometheus", "grafana/grafana"}},
				},
			},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal VersionSkewResponse: %v", err)
	}

	var decoded VersionSkewResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.TotalSkewedPackages != 42 {
		t.Errorf("expected total 42, got %d", decoded.TotalSkewedPackages)
	}
	if decoded.Page != 1 {
		t.Errorf("expected page 1, got %d", decoded.Page)
	}
	if len(decoded.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(decoded.Items))
	}

	item := decoded.Items[0]
	if item.PackageName != "golang.org/x/net" {
		t.Errorf("expected golang.org/x/net, got %s", item.PackageName)
	}
	if item.VersionCount != 3 {
		t.Errorf("expected 3 versions, got %d", item.VersionCount)
	}
	if len(item.Versions) != 2 {
		t.Fatalf("expected 2 version details, got %d", len(item.Versions))
	}
	if len(item.Versions[0].Projects) != 3 {
		t.Errorf("expected 3 projects for v0.17.0, got %d", len(item.Versions[0].Projects))
	}
	if item.Versions[1].Projects[0] != "prometheus/prometheus" {
		t.Errorf("expected prometheus/prometheus, got %s", item.Versions[1].Projects[0])
	}
}

func TestVersionSkewEmptyResponse(t *testing.T) {
	resp := VersionSkewResponse{
		TotalSkewedPackages: 0,
		Page:                1,
		PageSize:            50,
		Items:               []VersionSkewItem{},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal empty response: %v", err)
	}

	// Ensure items is [] not null.
	if string(data) == "" {
		t.Fatal("empty JSON")
	}

	var decoded VersionSkewResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Items == nil {
		t.Error("Items should be empty slice, not nil")
	}
}

