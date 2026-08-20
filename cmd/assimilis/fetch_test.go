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
	"github.com/traefik/assimilis/v2/pkg/generator"
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
	assert.Equal(t, "2026-08-07T12:00:00Z\n", string(timestamp))
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
	require.ErrorIs(t, statErr, os.ErrNotExist)
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
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestFetchDoesNotChangeFilesWhenInvalidSBOM(t *testing.T) {
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
		staticDownloader{sbom: []byte(`{"bomFormat":`)},
		func(context.Context, generator.Config) error {
			t.Fatal("generator should not be called")

			return nil
		},
		time.Now,
	)
	require.ErrorContains(t, err, "invalid SBOM returned by Aikido")

	_, statErr := os.Stat(filepath.Join(cfg.SBOMPath, "repo.cdx.json"))
	require.ErrorIs(t, statErr, os.ErrNotExist)

	_, statErr = os.Stat(filepath.Join(outDir, ".last_generated_at"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestValidateSBOM(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expectedError string
	}{
		{
			name:  "valid CycloneDX",
			input: `{"bomFormat":"CycloneDX"}`,
		},
		{
			name:          "invalid JSON",
			input:         `{"bomFormat":`,
			expectedError: "failed to decode JSON",
		},
		{
			name:          "missing format",
			input:         `{}`,
			expectedError: `unexpected bomFormat ""`,
		},
		{
			name:          "unexpected format",
			input:         `{"bomFormat":"SPDX"}`,
			expectedError: `unexpected bomFormat "SPDX"`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			expectedError := validateSBOM([]byte(testCase.input))

			if testCase.expectedError == "" {
				require.NoError(t, expectedError)

				return
			}

			require.ErrorContains(t, expectedError, testCase.expectedError)
		})
	}
}
