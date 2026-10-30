package pnpm

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type PackageResolution struct {
	Tarball string `yaml:"tarball,omitempty"`
}

type PackageInfo struct {
	Resolution      PackageResolution `yaml:"resolution"`
	Dependencies    map[string]string `yaml:"dependencies,omitempty"`
	DevDependencies map[string]string `yaml:"devDependencies,omitempty"`
	IsDev           bool              `yaml:"dev,omitempty"`
	Name            string            `yaml:"name,omitempty"`
	Version         string            `yaml:"version,omitempty"`
}

type LockFile struct {
	LockfileVersion any                    `yaml:"lockfileVersion"`
	Dependencies    map[string]any         `yaml:"dependencies,omitempty"`
	DevDependencies map[string]any         `yaml:"devDependencies,omitempty"`
	Packages        map[string]PackageInfo `yaml:"packages,omitempty"`

	// V9
	Importers map[string]Importer `yaml:"importers,omitempty"`
	Snapshots map[string]Snapshot `yaml:"snapshots,omitempty"`
}

type Importer struct {
	Dependencies    map[string]ImporterDepVersion `yaml:"dependencies,omitempty"`
	DevDependencies map[string]ImporterDepVersion `yaml:"devDependencies,omitempty"`
}

type ImporterDepVersion struct {
	Version string `yaml:"version,omitempty"`
}

type Snapshot struct {
	Dependencies         map[string]string `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies,omitempty"`
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("pnpm"),
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	if err := yaml.NewDecoder(r).Decode(&lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	lockVer := p.parseLockfileVersion(lockFile)
	if lockVer < 0 {
		return nil, nil, nil
	}

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	if lockVer >= 9 {
		pkgs, deps = p.parseV9(lockFile)
	} else {
		pkgs, deps = p.parse(lockVer, lockFile)
	}

	// Peer contexts can share name, version and relationship. Use the graph ID
	// to break ties so map iteration does not affect package ordering.
	sort.Slice(pkgs, func(i, j int) bool {
		packages := ftypes.Packages(pkgs)
		if packages.Less(i, j) {
			return true
		}
		if packages.Less(j, i) {
			return false
		}
		return pkgs[i].ID < pkgs[j].ID
	})
	sort.Sort(ftypes.Dependencies(deps))
	return pkgs, deps, nil
}

func (p *Parser) parse(lockVer float64, lockFile LockFile) ([]ftypes.Package, []ftypes.Dependency) {
	var pkgs []ftypes.Package
	var deps []ftypes.Dependency

	// Dependency path is a path to a dependency with a specific set of resolved subdependencies.
	// cf. https://github.com/pnpm/spec/blob/ad27a225f81d9215becadfa540ef05fa4ad6dd60/dependency-path.md
	for depPath, info := range lockFile.Packages {
		if info.IsDev {
			continue
		}

		// Dependency name may be present in dependencyPath or Name field. Same for Version.
		// e.g. packages installed from local directory or tarball
		// cf. https://github.com/pnpm/spec/blob/274ff02de23376ad59773a9f25ecfedd03a41f64/lockfile/6.0.md#packagesdependencypathname
		name := info.Name
		version := info.Version
		var ref string

		if name == "" {
			name, version, ref = p.parseDepPath(depPath, lockVer)
			version = p.parseVersion(depPath, version, lockVer)
		}
		pkgID := packageID(name, version)

		dependencies := make([]string, 0, len(info.Dependencies))
		for depName, depVer := range info.Dependencies {
			dependencies = append(dependencies, packageID(depName, depVer))
		}

		pkgs = append(pkgs, ftypes.Package{
			ID:                 pkgID,
			Name:               name,
			Version:            version,
			Relationship:       lo.Ternary(isDirectPkg(name, lockFile.Dependencies), ftypes.RelationshipDirect, ftypes.RelationshipIndirect),
			ExternalReferences: toExternalRefs(ref),
		})

		if len(dependencies) > 0 {
			sort.Strings(dependencies)
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependencies,
			})
		}
	}

	return pkgs, deps
}

func (p *Parser) parseV9(lockFile LockFile) ([]ftypes.Package, []ftypes.Dependency) {
	lockVer := 9.0
	resolvedPkgs := make(map[string]ftypes.Package)
	resolvedDeps := make(map[string]ftypes.Dependency)

	// A package can have several snapshots with different resolved peers. Keep
	// the snapshot path as its graph identity, but use package metadata for the
	// version used by vulnerability matching.
	paths := make(map[string]string) // snapshot path => package metadata path
	for depPath := range lockFile.Snapshots {
		base := p.trimPeerDeps(depPath, lockVer)
		if _, ok := lockFile.Packages[base]; ok {
			paths[depPath] = base
		}
	}
	// Retain package metadata even when a lockfile has no corresponding snapshot.
	withSnapshots := set.New[string]()
	for _, base := range paths {
		withSnapshots.Append(base)
	}
	for depPath := range lockFile.Packages {
		if !withSnapshots.Contains(depPath) {
			paths[depPath] = depPath
		}
	}

	ids := make(map[string]string, len(paths))
	for depPath, base := range paths {
		pkgInfo := lockFile.Packages[base]
		name, ver, ref := p.parseDepPath(base, lockVer)
		parsedVer := p.parseVersion(base, ver, lockVer)
		if pkgInfo.Version != "" {
			parsedVer = pkgInfo.Version
		}
		id := packageID(name, parsedVer)
		if depPath != base {
			id = depPath
		}
		ids[depPath] = id
		resolvedPkgs[id] = ftypes.Package{
			ID:                 id,
			Name:               name,
			Version:            parsedVer,
			Relationship:       ftypes.RelationshipIndirect,
			Dev:                true,
			ExternalReferences: toExternalRefs(ref),
		}
	}

	// Alias values contain the actual package name; ordinary values contain
	// only the version (including its peer context).
	resolve := func(name, version string) (string, bool) {
		id, ok := ids[packageID(name, version)]
		if !ok {
			id, ok = ids[version]
		}
		return id, ok
	}
	for depPath, snapshot := range lockFile.Snapshots {
		id, ok := ids[depPath]
		if !ok {
			continue
		}
		dependsOn := set.New[string]()
		for name, version := range lo.Assign(snapshot.OptionalDependencies, snapshot.Dependencies) {
			if depID, ok := resolve(name, version); ok {
				dependsOn.Append(depID)
			}
		}
		if dependsOn.Size() > 0 {
			children := dependsOn.Items()
			sort.Strings(children)
			resolvedDeps[id] = ftypes.Dependency{ID: id, DependsOn: children}
		}
	}

	// Process every importer independently: different workspaces can directly
	// require different versions or peer contexts of the same package.
	markDirect := func(name, version string, dev bool) {
		if id, ok := resolve(name, version); ok {
			pkg := resolvedPkgs[id]
			pkg.Relationship = ftypes.RelationshipDirect
			pkg.Dev = pkg.Dev && dev
			resolvedPkgs[id] = pkg
		}
	}
	for _, importer := range lockFile.Importers {
		for name, dep := range importer.DevDependencies {
			markDirect(name, dep.Version, true)
		}
		for name, dep := range importer.Dependencies {
			markDirect(name, dep.Version, false)
		}
	}

	visited := set.New[string]()
	// Overwrite the `Dev` field for dev deps and their child dependencies.
	for _, pkg := range resolvedPkgs {
		if !pkg.Dev {
			p.markRootPkgs(pkg.ID, resolvedPkgs, resolvedDeps, visited)
		}
	}

	return lo.Values(resolvedPkgs), lo.Values(resolvedDeps)
}

// markRootPkgs sets `Dev` to false for non dev dependency.
func (p *Parser) markRootPkgs(id string, pkgs map[string]ftypes.Package, deps map[string]ftypes.Dependency, visited set.Set[string]) {
	if visited.Contains(id) {
		return
	}
	pkg, ok := pkgs[id]
	if !ok {
		return
	}

	pkg.Dev = false
	pkgs[id] = pkg
	visited.Append(id)

	// Update child deps
	for _, depID := range deps[id].DependsOn {
		p.markRootPkgs(depID, pkgs, deps, visited)
	}
}

func (p *Parser) parseLockfileVersion(lockFile LockFile) float64 {
	switch v := lockFile.LockfileVersion.(type) {
	// v5
	case float64:
		return v
	// v6+
	case string:
		lockVer, err := strconv.ParseFloat(v, 64)
		if err != nil {
			p.logger.Debug("Unable to convert the lock file version to float", log.Err(err))
			return -1
		}
		return lockVer
	default:
		p.logger.Debug("Unknown type for the lock file version",
			log.Any("version", lockFile.LockfileVersion))
		return -1
	}
}

func (p *Parser) parseDepPath(depPath string, lockVer float64) (string, string, string) {
	dPath, nonDefaultRegistry := p.trimRegistry(depPath, lockVer)

	var scope string
	scope, dPath = p.separateScope(dPath)

	var name string
	name, dPath = p.separateName(dPath, lockVer)

	// add scope to pkg name
	if scope != "" {
		name = fmt.Sprintf("%s/%s", scope, name)
	}

	ver := p.trimPeerDeps(dPath, lockVer)

	return name, ver, lo.Ternary(nonDefaultRegistry, depPath, "")
}

// trimRegistry trims registry (or `/` prefix) for depPath.
// It returns true if non-default registry has been trimmed.
// e.g.
//   - "registry.npmjs.org/lodash/4.17.10" => "lodash/4.17.10", false
//   - "registry.npmjs.org/@babel/generator/7.21.9" => "@babel/generator/7.21.9", false
//   - "private.npm.org/@babel/generator/7.21.9" => "@babel/generator/7.21.9", true
//   - "/lodash/4.17.10" => "lodash/4.17.10", false
//   - "/asap@2.0.6" => "asap@2.0.6", false
func (p *Parser) trimRegistry(depPath string, lockVer float64) (string, bool) {
	var nonDefaultRegistry bool
	// lock file v9 doesn't use registry prefix
	if lockVer < 9 {
		var registry string
		registry, depPath, _ = strings.Cut(depPath, "/")
		if registry != "" && registry != "registry.npmjs.org" {
			nonDefaultRegistry = true
		}
	}
	return depPath, nonDefaultRegistry
}

// separateScope separates the scope (if set) from the rest of the depPath.
// e.g.
//   - v5:  "@babel/generator/7.21.9" => {"babel", "generator/7.21.9"}
//   - v6+: "@babel/helper-annotate-as-pure@7.18.6" => "{"babel", "helper-annotate-as-pure@7.18.6"}
func (p *Parser) separateScope(depPath string) (string, string) {
	var scope string
	if strings.HasPrefix(depPath, "@") {
		scope, depPath, _ = strings.Cut(depPath, "/")
	}
	return scope, depPath
}

// separateName separates pkg name and version.
// e.g.
//   - v5:  "generator/7.21.9" => {"generator", "7.21.9"}
//   - v6+: "7.21.5(@babel/core@7.20.7)" => "7.21.5"
//
// for v9+ version can be filePath or link:
//   - "package1@file:package1:"
//   - "is-negative@https://codeload.github.com/zkochan/is-negative/tar.gz/2fa0531ab04e300a24ef4fd7fb3a280eccb7ccc5"
//
// Also version can contain peer deps:
//   - "debug@4.3.4(supports-color@8.1.1)"
func (p *Parser) separateName(depPath string, lockVer float64) (string, string) {
	sep := "@"
	if lockVer < 6 {
		sep = "/"
	}
	name, version, _ := strings.Cut(depPath, sep)
	return name, version
}

// Trim peer deps
// e.g.
//   - v5:  "7.21.5_@babel+core@7.21.8" => "7.21.5"
//   - v6+: "7.21.5(@babel/core@7.20.7)" => "7.21.5"
func (p *Parser) trimPeerDeps(depPath string, lockVer float64) string {
	sep := "("
	if lockVer < 6 {
		sep = "_"
	}
	version, _, _ := strings.Cut(depPath, sep)
	return version
}

// parseVersion parses version.
// v9 can use filePath or link as version - we need to clear these versions.
// e.g.
//   - "package1@file:package1:"
//   - "is-negative@https://codeload.github.com/zkochan/is-negative/tar.gz/2fa0531ab04e300a24ef4fd7fb3a280eccb7ccc5"
//
// Other versions should be semver valid.
func (p *Parser) parseVersion(depPath, ver string, lockVer float64) string {
	if lockVer < 9 && (strings.HasPrefix(ver, "file:") || strings.HasPrefix(ver, "http")) {
		return ""
	}
	if _, err := semver.Parse(ver); err != nil {
		p.logger.Debug("Skip non-semver package", log.String("pkg_path", depPath),
			log.String("version", ver), log.Err(err))
		return ""
	}

	return ver
}

func isDirectPkg(name string, directDeps map[string]any) bool {
	_, ok := directDeps[name]
	return ok
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Pnpm, name, version)
}

func toExternalRefs(ref string) []ftypes.ExternalRef {
	if ref == "" {
		return nil
	}
	return []ftypes.ExternalRef{
		{
			Type: ftypes.RefVCS,
			URL:  ref,
		},
	}
}
