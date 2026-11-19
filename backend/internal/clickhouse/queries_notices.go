package clickhouse

import (
	"context"
	"fmt"

	"github.com/seebom-labs/bomhort/backend/internal/clearlydefined"
)

// QuerySBOMPackagesForNotice returns the target name and the list of packages
// for generating an attribution NOTICE file for a specific SBOM (#530).
func (c *Client) QuerySBOMPackagesForNotice(ctx context.Context, sbomID string) (string, []clearlydefined.NoticePackage, error) {
	var docName, docVersion string
	err := c.Conn.QueryRow(ctx, `
		SELECT document_name, document_version
		FROM sboms FINAL
		WHERE sbom_id = ?
		LIMIT 1
	`, sbomID).Scan(&docName, &docVersion)
	if isNoRows(err) {
		return "", nil, ErrSBOMNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("failed to query sbom for notice %s: %w", sbomID, err)
	}

	targetName := docName
	if docVersion != "" {
		targetName = fmt.Sprintf("%s (%s)", docName, docVersion)
	}

	var names, versions, purls, licenses []string
	err = c.Conn.QueryRow(ctx, `
		SELECT package_names, package_versions, package_purls, package_licenses
		FROM sbom_packages FINAL
		WHERE sbom_id = ?
		LIMIT 1
	`, sbomID).Scan(&names, &versions, &purls, &licenses)
	if isNoRows(err) {
		return targetName, []clearlydefined.NoticePackage{}, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("failed to query packages for notice %s: %w", sbomID, err)
	}

	pkgs := make([]clearlydefined.NoticePackage, len(names))
	for i := range names {
		p := clearlydefined.NoticePackage{
			Name: names[i],
		}
		if i < len(versions) {
			p.Version = versions[i]
		}
		if i < len(purls) {
			p.PURL = purls[i]
		}
		if i < len(licenses) {
			p.License = licenses[i]
		}
		pkgs[i] = p
	}

	return targetName, pkgs, nil
}

// QueryProjectPackagesForNotice returns the target name and packages for generating
// an attribution NOTICE file for a project, optionally filtered by version (#530).
func (c *Client) QueryProjectPackagesForNotice(ctx context.Context, projectName, version string) (string, []clearlydefined.NoticePackage, error) {
	var targetSBOMID string
	if version != "" {
		id, err := c.QueryProjectSBOMIDByVersion(ctx, projectName, version)
		if err != nil {
			return "", nil, err
		}
		targetSBOMID = id
	} else {
		detail, err := c.QueryProjectDetail(ctx, projectName)
		if err != nil {
			return "", nil, err
		}
		if detail.LatestSBOMID == "" {
			return "", nil, ErrSBOMNotFound
		}
		targetSBOMID = detail.LatestSBOMID
	}

	return c.QuerySBOMPackagesForNotice(ctx, targetSBOMID)
}
