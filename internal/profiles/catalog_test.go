package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProfile(t *testing.T, root, name, manifestJSON string, files map[string][]byte) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifestJSON), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest.json) error = %v", err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", name, err)
		}
	}
}

func TestLoadCatalog_LoadsValidProfile(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "warcraft3-1.26a", `{
		"product": "W3XP",
		"profileId": "warcraft3-1.26a",
		"versionByte": 26,
		"exeVersion": 16777242,
		"exeInfoTemplate": "war3.exe 03/24/09 03:00:00 123456",
		"hashFiles": ["war3.exe"]
	}`, map[string][]byte{"war3.exe": {0x4D, 0x5A}})

	catalog, err := LoadCatalog(root, map[string]string{"W3XP": "warcraft3-1.26a"})
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	if catalog.Len() != 1 {
		t.Fatalf("catalog.Len() = %d, want 1", catalog.Len())
	}

	p, ok := catalog.Get("W3XP", "warcraft3-1.26a")
	if !ok {
		t.Fatal("catalog.Get() ok = false, want true")
	}
	if p.VersionByte != 26 {
		t.Errorf("p.VersionByte = %d, want 26", p.VersionByte)
	}
	if len(p.FileHashCodes) != 1 || p.FileHashCodes[0] != 0 {
		t.Errorf("p.FileHashCodes = %v, want [0] (default when omitted from manifest)", p.FileHashCodes)
	}

	def, ok := catalog.Default("W3XP")
	if !ok || def != p {
		t.Errorf("catalog.Default(\"W3XP\") = %v, %v, want the same profile", def, ok)
	}
}

func TestLoadCatalog_MissingHashFile_ReturnsError(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "broken", `{
		"product": "W3XP",
		"profileId": "broken",
		"versionByte": 26,
		"hashFiles": ["does-not-exist.exe"]
	}`, nil)

	if _, err := LoadCatalog(root, nil); err == nil {
		t.Error("LoadCatalog() error = nil, want an error for a manifest referencing a missing file")
	}
}

func TestLoadCatalog_IgnoresNonProfileDirectories(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "not-a-profile"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	catalog, err := LoadCatalog(root, nil)
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	if catalog.Len() != 0 {
		t.Errorf("catalog.Len() = %d, want 0", catalog.Len())
	}
}

func TestLoadCatalog_ExplicitFileHashCodes_ArePreserved(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "diablo2", `{
		"product": "D2DV",
		"profileId": "diablo2",
		"hashFiles": ["Game.exe", "Storm.dll"],
		"fileHashCodes": [3, 5]
	}`, map[string][]byte{"Game.exe": {1}, "Storm.dll": {2}})

	catalog, err := LoadCatalog(root, nil)
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}

	p, ok := catalog.Get("D2DV", "diablo2")
	if !ok {
		t.Fatal("catalog.Get() ok = false, want true")
	}
	want := []uint32{3, 5}
	if len(p.FileHashCodes) != 2 || p.FileHashCodes[0] != want[0] || p.FileHashCodes[1] != want[1] {
		t.Errorf("p.FileHashCodes = %v, want %v", p.FileHashCodes, want)
	}

	files, err := p.LoadFiles()
	if err != nil {
		t.Fatalf("p.LoadFiles() error = %v", err)
	}
	if len(files) != 2 || files[0][0] != 1 || files[1][0] != 2 {
		t.Errorf("p.LoadFiles() = %v, want [[1] [2]]", files)
	}
}

func TestDefault_UnknownProduct_ReturnsFalse(t *testing.T) {
	catalog, err := LoadCatalog(t.TempDir(), map[string]string{})
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	if _, ok := catalog.Default("NOPE"); ok {
		t.Error("catalog.Default(\"NOPE\") ok = true, want false")
	}
}
