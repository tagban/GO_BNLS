// Package config loads openbnls's top-level JSON configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is openbnls's top-level configuration.
type Config struct {
	ListenPort                int               `json:"listenPort"`
	StatsPort                 int               `json:"statsPort"`
	ProfilesDirectory         string            `json:"profilesDirectory"`
	SharedSecret              string            `json:"sharedSecret"`
	DefaultProfileIDByProduct map[string]string `json:"defaultProfileIdByProduct"`
}

// Default returns a Config with sane defaults for a fresh install.
func Default() *Config {
	return &Config{
		ListenPort:                9367,
		StatsPort:                 9368,
		ProfilesDirectory:         "./profiles",
		SharedSecret:              "Invigoration",
		DefaultProfileIDByProduct: map[string]string{},
	}
}

// Load reads and parses a JSON config file, filling in Default's values for
// any field the file doesn't set.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	c := Default()
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	return c, nil
}
