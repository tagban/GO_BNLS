// Package profiles loads per-product, per-patch "game file profile"
// directories: the version byte to answer BNLS_REQUESTVERSIONBYTE with, and
// the real game files (operator-supplied, never fetched by this project —
// see the README) CheckRevision hashes.
package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Profile describes one product/patch's CheckRevision inputs and the
// version byte to answer BNLS_REQUESTVERSIONBYTE with. One directory per
// profile, containing a manifest.json plus the files it references.
type Profile struct {
	Product         string   `json:"product"`
	ProfileID       string   `json:"profileId"`
	VersionByte     uint32   `json:"versionByte"`
	ExeVersion      uint32   `json:"exeVersion"`
	ExeInfoTemplate string   `json:"exeInfoTemplate"`
	HashFiles       []string `json:"hashFiles"`

	dir string // directory containing manifest.json and the hash files
}

// LoadFiles reads this profile's hash files from disk, in manifest order.
func (p *Profile) LoadFiles() ([][]byte, error) {
	files := make([][]byte, len(p.HashFiles))
	for i, name := range p.HashFiles {
		data, err := os.ReadFile(filepath.Join(p.dir, name))
		if err != nil {
			return nil, fmt.Errorf("profile %s/%s: reading hash file %q: %w", p.Product, p.ProfileID, name, err)
		}
		files[i] = data
	}
	return files, nil
}

func loadProfile(dir string) (*Profile, error) {
	manifestPath := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", manifestPath, err)
	}

	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", manifestPath, err)
	}
	p.dir = dir

	if len(p.HashFiles) == 0 {
		return nil, fmt.Errorf("%s: manifest has no hashFiles", manifestPath)
	}

	// Fail fast on a missing hash file: a wrong/incomplete CheckRevision
	// answer is worse than refusing to start.
	for _, name := range p.HashFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return nil, fmt.Errorf("%s: hash file %q: %w", manifestPath, name, err)
		}
	}

	return &p, nil
}
