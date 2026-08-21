package server

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/tagban/GO_BNLS/internal/profiles"
)

// Server accepts BNLS TCP connections and dispatches each to its own Session.
type Server struct {
	catalog      *profiles.Catalog
	sharedSecret string
	logger       *log.Logger
	stats        *Stats

	listener net.Listener
}

// New returns a Server ready to serve on a listener.
func New(catalog *profiles.Catalog, sharedSecret string, logger *log.Logger) *Server {
	return &Server{
		catalog:      catalog,
		sharedSecret: sharedSecret,
		logger:       logger,
		stats:        NewStats(),
	}
}

// Stats returns the server's connection counters, for a stats endpoint to read.
func (srv *Server) Stats() *Stats { return srv.stats }

// ListenAndServe listens on addr (e.g. ":9367") and serves connections
// until the listener is closed, at which point it returns nil.
func (srv *Server) ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	return srv.Serve(listener)
}

// Serve accepts connections on an already-open listener until it's closed.
func (srv *Server) Serve(listener net.Listener) error {
	srv.listener = listener
	defer listener.Close()

	srv.logger.Printf("listening on %s", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}

		srv.stats.RecordConnection()
		session := newSession(conn, srv.catalog, srv.sharedSecret, srv.logger, srv.stats)
		go session.Serve()
	}
}

// Close stops the listener, causing Serve/ListenAndServe to return.
func (srv *Server) Close() error {
	if srv.listener == nil {
		return nil
	}
	return srv.listener.Close()
}
