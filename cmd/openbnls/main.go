// Command openbnls runs the BNLS server.
//
// Phase 0 scaffold: prints its intended listen address and exits. The real
// accept loop, opcode handlers, and CheckRevision implementation land in
// later phases — see the project README's Roadmap section.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	listenAddr := flag.String("listen", ":9367", "address to listen on (default BNLS port)")
	flag.Parse()

	fmt.Fprintf(os.Stdout, "openbnls: scaffold build, would listen on %s (not yet implemented)\n", *listenAddr)
}
