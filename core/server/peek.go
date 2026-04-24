package server

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"sync"
	"time"

	"lancarsec/core/firewall"
	"lancarsec/core/tlsparse"
)

// peekListener wraps a net.Listener and returns connections that stash a
// parsed ClientHello in firewall.ClientHellos keyed by remote addr before the
// TLS handshake reads the same bytes. This is the only way to get the raw
// extension list and signature algorithm vector that Go's
// tls.ClientHelloInfo doesn't expose.
type peekListener struct {
	net.Listener
}

func (p *peekListener) Accept() (net.Conn, error) {
	c, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newPeekConn(c), nil
}

type peekConn struct {
	net.Conn
	r    *bufio.Reader
	once sync.Once
}

// peekBufSize is large enough to fit any realistic ClientHello (typically
// under 2 KB; pathological clients stretch to ~8 KB with many extensions).
const peekBufSize = 64 * 1024

func newPeekConn(c net.Conn) *peekConn {
	return &peekConn{
		Conn: c,
		r:    bufio.NewReaderSize(c, peekBufSize),
	}
}

// Read serves bytes from the bufio buffer (which still holds the peeked
// ClientHello) first, then falls through to the underlying conn. tls.Server
// reads via this, so it sees exactly the original bytes.
func (p *peekConn) Read(b []byte) (int, error) {
	p.once.Do(p.parseClientHello)
	return p.r.Read(b)
}

func (p *peekConn) parseClientHello() {
	// Brief deadline so a peer that opens a socket and never speaks TLS
	// doesn't pin a goroutine. Restored to zero (no deadline) so the real
	// handshake isn't affected.
	_ = p.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = p.Conn.SetReadDeadline(time.Time{}) }()

	hdr, err := p.r.Peek(5)
	if err != nil || hdr[0] != 0x16 {
		return
	}
	recordLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recordLen <= 0 || recordLen > peekBufSize-5 {
		return
	}
	full, err := p.r.Peek(5 + recordLen)
	if err != nil {
		return
	}
	hello, ok := tlsparse.ParseRecord(full)
	if !ok {
		return
	}
	firewall.ClientHellos.Store(p.Conn.RemoteAddr().String(), hello)
}

// listenAndServeTLSPeek is the origin-mode equivalent of
// http.Server.ListenAndServeTLS that wires peekListener between the raw
// socket and tls.NewListener so the ClientHello is captured before the TLS
// stack consumes it.
func listenAndServeTLSPeek(s *http.Server) error {
	addr := s.Addr
	if addr == "" {
		addr = ":https"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	peekLn := &peekListener{Listener: ln}
	tlsLn := tls.NewListener(peekLn, s.TLSConfig)
	return s.Serve(tlsLn)
}
