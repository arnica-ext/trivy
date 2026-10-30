package cyclonedx_test

import (
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/pnpm"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestPNPMPeerContextGraph(t *testing.T) {
	const lock = `lockfileVersion: '9.0'
packages:
  follow-redirects@1.15.11: {}
  debug@4.3.6: {}
  debug@4.4.3: {}
snapshots:
  follow-redirects@1.15.11(debug@4.3.6):
    dependencies:
      debug: 4.3.6
  follow-redirects@1.15.11(debug@4.4.3):
    dependencies:
      debug: 4.4.3
  debug@4.3.6: {}
  debug@4.4.3: {}
`
	for range 10 {
		app, err := language.Parse(ftypes.Pnpm, "pnpm-lock.yaml", strings.NewReader(lock), pnpm.NewParser())
		require.NoError(t, err)
		for i := range app.Packages {
			pkg := &app.Packages[i]
			pkg.Identifier.UID = dependency.UID(app.FilePath, *pkg)
			pkg.Identifier.PURL = &packageurl.PackageURL{Type: packageurl.TypeNPM, Name: pkg.Name, Version: pkg.Version}
		}
		marshaler := cyclonedx.NewMarshaler("test")
		bom, err := marshaler.MarshalReport(t.Context(), types.Report{ArtifactName: "pnpm-project", ArtifactType: ftypes.TypeFilesystem, Results: types.Results{{
			Target: app.FilePath, Class: types.ClassLangPkg, Type: ftypes.Pnpm, Packages: app.Packages,
		}}})
		require.NoError(t, err)
		ids := map[string]string{}
		contexts := 0
		for _, component := range *bom.Components {
			if component.Properties != nil {
				for _, prop := range *component.Properties {
					if prop.Name == cyclonedx.Namespace+core.PropertyPkgID {
						ids[component.BOMRef] = prop.Value
					}
				}
			}
			if component.Name == "follow-redirects" {
				contexts++
				require.Equal(t, "1.15.11", component.Version)
				require.Equal(t, "pkg:npm/follow-redirects@1.15.11", component.PackageURL)
			}
		}
		require.Equal(t, 2, contexts)
		graph := map[string][]string{}
		for _, dep := range *bom.Dependencies {
			if id, ok := ids[dep.Ref]; ok {
				graph[id] = []string{}
				for _, ref := range *dep.Dependencies {
					require.Contains(t, ids, ref)
					graph[id] = append(graph[id], ids[ref])
				}
			}
		}
		require.Equal(t, map[string][]string{
			"follow-redirects@1.15.11(debug@4.3.6)": {"debug@4.3.6"},
			"follow-redirects@1.15.11(debug@4.4.3)": {"debug@4.4.3"},
			"debug@4.3.6":                           {},
			"debug@4.4.3":                           {},
		}, graph)
	}
}
