package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_FillsInDefaultsForMissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openbnls.json")
	if err := os.WriteFile(path, []byte(`{"listenPort": 12345}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if c.ListenPort != 12345 {
		t.Errorf("ListenPort = %d, want 12345 (from file)", c.ListenPort)
	}
	if c.StatsPort != 9368 {
		t.Errorf("StatsPort = %d, want 9368 (default)", c.StatsPort)
	}
	if c.ProfilesDirectory != "./profiles" {
		t.Errorf("ProfilesDirectory = %q, want %q (default)", c.ProfilesDirectory, "./profiles")
	}
}

func TestLoad_MissingFile_ReturnsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Error("Load() error = nil, want an error for a missing file")
	}
}

func TestLoad_InvalidJSON_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openbnls.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Error("Load() error = nil, want an error for invalid JSON")
	}
}
