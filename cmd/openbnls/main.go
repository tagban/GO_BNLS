// Command openbnls runs the BNLS server.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/tagban/GO_BNLS/internal/config"
	"github.com/tagban/GO_BNLS/internal/profiles"
	"github.com/tagban/GO_BNLS/internal/server"
)

func main() {
	configPath := flag.String("config", "", "path to a JSON config file (built-in defaults used if omitted)")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)

	cfg := config.Default()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			logger.Fatalf("loading config: %v", err)
		}
		cfg = loaded
	}

	catalog, err := profiles.LoadCatalog(cfg.ProfilesDirectory, cfg.DefaultProfileIDByProduct)
	if err != nil {
		logger.Fatalf("loading profiles from %q: %v", cfg.ProfilesDirectory, err)
	}
	logger.Printf("loaded %d profile(s) from %s", catalog.Len(), cfg.ProfilesDirectory)

	srv := server.New(catalog, cfg.SharedSecret, logger)
	addr := fmt.Sprintf(":%d", cfg.ListenPort)
	if err := srv.ListenAndServe(addr); err != nil {
		logger.Fatalf("server: %v", err)
	}
}
