package server

import "sync"

// Stats holds simple connection counters, mirroring the kind of breakdown
// bnls.bnetdocs.org's own JBLS stats page shows ("WAR3 Keys: N connections"
// etc). The HTTP endpoint that exposes these is Phase 3 — this is just the
// counter storage, wired in now so handlers can record against it as
// they're written rather than retrofitting later.
type Stats struct {
	mu                 sync.Mutex
	connectionsTotal   int
	connectionsByProduct map[string]int
}

// NewStats returns an empty Stats.
func NewStats() *Stats {
	return &Stats{connectionsByProduct: make(map[string]int)}
}

// RecordConnection increments the total connection counter.
func (s *Stats) RecordConnection() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectionsTotal++
}

// RecordProductRequest increments the counter for one product's requests
// (e.g. a REQUESTVERSIONBYTE or CDKEY_EX call for that product).
func (s *Stats) RecordProductRequest(product string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectionsByProduct[product]++
}

// Snapshot returns a point-in-time copy of the counters, safe to read
// without further locking.
func (s *Stats) Snapshot() (total int, byProduct map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byProduct = make(map[string]int, len(s.connectionsByProduct))
	for k, v := range s.connectionsByProduct {
		byProduct[k] = v
	}
	return s.connectionsTotal, byProduct
}
