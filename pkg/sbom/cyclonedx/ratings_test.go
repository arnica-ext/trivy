package cyclonedx

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

func TestMarshaler_ratings(t *testing.T) {
	tests := []struct {
		name string
		vuln core.Vulnerability
		want []cdx.VulnerabilityRating
	}{
		{
			name: "CVSSv2 + CVSSv3",
			vuln: core.Vulnerability{
				Vulnerability: dtypes.Vulnerability{
					VendorSeverity: dtypes.VendorSeverity{
						vulnerability.NVD: dtypes.SeverityMedium,
					},
					CVSS: dtypes.VendorCVSS{
						vulnerability.NVD: dtypes.CVSS{
							V2Vector: "AV:N/AC:M/Au:N/C:N/I:N/A:P",
							V2Score:  4.3,
							V3Vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
							V3Score:  5.5,
						},
					},
				},
			},
			want: []cdx.VulnerabilityRating{
				{
					Source:   &cdx.Source{Name: string(vulnerability.NVD)},
					Score:    lo.ToPtr(4.3),
					Severity: cdx.SeverityMedium,
					Method:   cdx.ScoringMethodCVSSv2,
					Vector:   "AV:N/AC:M/Au:N/C:N/I:N/A:P",
				},
				{
					Source:   &cdx.Source{Name: string(vulnerability.NVD)},
					Score:    lo.ToPtr(5.5),
					Severity: cdx.SeverityMedium,
					Method:   cdx.ScoringMethodCVSSv3,
					Vector:   "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
				},
			},
		},
		{
			// Reproduces https://github.com/aquasecurity/trivy/issues/...
			// GHSA advisories increasingly carry only CVSSv4 metrics, which were
			// previously dropped by the marshaler, leaving an empty Ratings array.
			name: "CVSSv4 only is preserved",
			vuln: core.Vulnerability{
				Vulnerability: dtypes.Vulnerability{
					VendorSeverity: dtypes.VendorSeverity{
						vulnerability.GHSA: dtypes.SeverityMedium,
					},
					CVSS: dtypes.VendorCVSS{
						vulnerability.GHSA: dtypes.CVSS{
							V40Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
							V40Score:  6.9,
						},
					},
				},
			},
			want: []cdx.VulnerabilityRating{
				{
					Source:   &cdx.Source{Name: string(vulnerability.GHSA)},
					Score:    lo.ToPtr(6.9),
					Severity: cdx.SeverityMedium,
					Method:   cdx.ScoringMethodCVSSv4,
					Vector:   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
				},
			},
		},
		{
			name: "CVSSv3 + CVSSv4 from the same source",
			vuln: core.Vulnerability{
				Vulnerability: dtypes.Vulnerability{
					VendorSeverity: dtypes.VendorSeverity{
						vulnerability.GHSA: dtypes.SeverityHigh,
					},
					CVSS: dtypes.VendorCVSS{
						vulnerability.GHSA: dtypes.CVSS{
							V3Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							V3Score:   9.8,
							V40Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
							V40Score:  9.3,
						},
					},
				},
			},
			want: []cdx.VulnerabilityRating{
				{
					Source:   &cdx.Source{Name: string(vulnerability.GHSA)},
					Score:    lo.ToPtr(9.8),
					Severity: cdx.SeverityHigh,
					Method:   cdx.ScoringMethodCVSSv31,
					Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
				{
					Source:   &cdx.Source{Name: string(vulnerability.GHSA)},
					Score:    lo.ToPtr(9.3),
					Severity: cdx.SeverityHigh,
					Method:   cdx.ScoringMethodCVSSv4,
					Vector:   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				},
			},
		},
		{
			name: "vendor severity without CVSS data",
			vuln: core.Vulnerability{
				Vulnerability: dtypes.Vulnerability{
					VendorSeverity: dtypes.VendorSeverity{
						vulnerability.GHSA: dtypes.SeverityLow,
					},
				},
			},
			want: []cdx.VulnerabilityRating{
				{
					Source:   &cdx.Source{Name: string(vulnerability.GHSA)},
					Severity: cdx.SeverityLow,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMarshaler("dev")
			got := m.ratings(tt.vuln)
			assert.Equal(t, tt.want, *got)
		})
	}
}
