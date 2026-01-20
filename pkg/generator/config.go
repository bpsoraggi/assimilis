// Package generator generates NOTICE/HTML attribution artifacts from a CycloneDX SBOM.
package generator

// Config the global configuration.
type Config struct {
	RepoName string

	SBOMPath         string
	HTMLTemplatePath string
	NoticeTplPath    string

	OutDir         string
	OutLicensesDir string

	SPDXVersion string
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	outDir := "third_party"
	outLicensesDir := outDir + "/licenses"
	sbomPath := outDir + "/sbom"

	return Config{
		SBOMPath: sbomPath,

		OutDir:         outDir,
		OutLicensesDir: outLicensesDir,

		SPDXVersion: "v3.27.0",
	}
}
