package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/assimilis/v3/pkg/generator"
)

const testRepoName = "repo"

type staticDownloader struct {
	sbom []byte
	err  error
}

func (d staticDownloader) DownloadSBOM(_ context.Context, _ string) ([]byte, error) {
	return d.sbom, d.err
}

func TestFetch(t *testing.T) {
	outDir := t.TempDir()
	cfg := generator.DefaultConfig()
	cfg.RepoName = testRepoName
	cfg.OutDir = outDir
	cfg.OutLicensesDir = filepath.Join(outDir, "licenses")
	cfg.SBOMPath = filepath.Join(outDir, "sbom")
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)

	err := fetch(
		context.Background(),
		cfg,
		"repo-code",
		staticDownloader{sbom: []byte(`{"bomFormat":"CycloneDX"}`)},
		func(_ context.Context, gotCfg generator.Config) error {
			sbom, readErr := os.ReadFile(filepath.Join(gotCfg.SBOMPath, "repo.cdx.json"))
			require.NoError(t, readErr)
			assert.JSONEq(t, `{"bomFormat":"CycloneDX"}`, string(sbom))

			return nil
		},
		func() time.Time { return now },
	)
	require.NoError(t, err)

	timestamp, err := os.ReadFile(filepath.Join(outDir, ".last_generated_at"))
	require.NoError(t, err)
	assert.Equal(t, "1786104000\n", string(timestamp))
}

func TestFetchDoesNotUpdateTimestampWhenFailure(t *testing.T) {
	outDir := t.TempDir()
	cfg := generator.DefaultConfig()
	cfg.RepoName = testRepoName
	cfg.OutDir = outDir
	cfg.OutLicensesDir = filepath.Join(outDir, "licenses")
	cfg.SBOMPath = filepath.Join(outDir, "sbom")

	err := fetch(
		context.Background(),
		cfg,
		"repo-code",
		staticDownloader{sbom: []byte(`{"bomFormat":"CycloneDX"}`)},
		func(context.Context, generator.Config) error { return errors.New("generation failed") },
		time.Now,
	)
	require.Error(t, err)

	_, statErr := os.Stat(filepath.Join(outDir, ".last_generated_at"))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestFetchDoesNotChangeFilesWhenDownloadFailure(t *testing.T) {
	outDir := t.TempDir()
	cfg := generator.DefaultConfig()
	cfg.RepoName = testRepoName
	cfg.OutDir = outDir
	cfg.OutLicensesDir = filepath.Join(outDir, "licenses")
	cfg.SBOMPath = filepath.Join(outDir, "sbom")

	err := fetch(
		context.Background(),
		cfg,
		"repo-code",
		staticDownloader{err: errors.New("download failed")},
		func(context.Context, generator.Config) error {
			t.Fatal("generator should not be called")

			return nil
		},
		time.Now,
	)
	require.Error(t, err)

	_, statErr := os.Stat(filepath.Join(cfg.SBOMPath, "repo.cdx.json"))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}
