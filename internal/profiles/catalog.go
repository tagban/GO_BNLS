package profiles

import (
	"fmt"
	"os"
	"path/filepath"
)

// Catalog holds every loaded profile, indexed by product and profile id,
// plus each product's configured default profile.
type Catalog struct {
	profiles       map[string]*Profile // key: product + "/" + profileID
	defaultProfile map[string]string   // product -> profileID
}

// LoadCatalog scans profilesDir for one subdirectory per profile (each
// containing a manifest.json), validating that every referenced hash file
// actually exists. Fails fast with a clear error rather than starting up
// and silently answering with a wrong checksum later.
func LoadCatalog(profilesDir string, defaultProfileIDByProduct map[string]string) (*Catalog, error) {
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil, fmt.Errorf("reading profiles directory %q: %w", profilesDir, err)
	}

	c := &Catalog{
		profiles:       make(map[string]*Profile),
		defaultProfile: defaultProfileIDByProduct,
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(profilesDir, entry.Name())
		manifestPath := filepath.Join(dir, "manifest.json")
		if _, err := os.Stat(manifestPath); err != nil {
			continue // not a profile directory (e.g. an empty placeholder dir)
		}

		p, err := loadProfile(dir)
		if err != nil {
			return nil, err
		}
		c.profiles[profileKey(p.Product, p.ProfileID)] = p
	}

	return c, nil
}

func profileKey(product, profileID string) string {
	return product + "/" + profileID
}

// Get returns the profile for an exact product+profileID, if loaded.
func (c *Catalog) Get(product, profileID string) (*Profile, bool) {
	p, ok := c.profiles[profileKey(product, profileID)]
	return p, ok
}

// Default returns the configured default profile for a product, if one is
// set and was loaded successfully.
func (c *Catalog) Default(product string) (*Profile, bool) {
	id, ok := c.defaultProfile[product]
	if !ok {
		return nil, false
	}
	return c.Get(product, id)
}

// Len returns the number of loaded profiles, mainly for logging/tests.
func (c *Catalog) Len() int { return len(c.profiles) }
