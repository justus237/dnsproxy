package upstream

import (
	"context"
	"errors"
	"fmt"
	"github.com/AdguardTeam/golibs/log"
	"io"
	"net"
	"os"
	"sync"
	"time"
	

	"github.com/joomcode/errorx"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"github.com/miekg/dns"
)

const handshakeTimeout = time.Second

type qLogWriter struct {
	filePath string
}

func (w qLogWriter) Write(p []byte) (n int, err error) {
	if string(p[:]) == "\n" {
		return 0, nil
	}
	//w.collector.QLogMessage(p)
	f, err := os.OpenFile(w.filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	n, errr := f.Write(p)
	f.WriteString("\n")
	if errr != nil {
		panic(errr)
	}
	return len(p), nil
}

func (w qLogWriter) Close() error {
	return nil
}

func newWriteCloser() io.WriteCloser {
	return &qLogWriter{filePath: "qlogs.txt"}
}

//
// DNS-over-QUIC
//
type dnsOverQUIC struct {
	boot       *bootstrapper
	session    quic.Session
	tokenStore quic.TokenStore
	version    quic.VersionNumber

	bytesPool    *sync.Pool // byte packets pool
	sync.RWMutex            // protects session and bytesPool
}

func (p *dnsOverQUIC) Reset() {
	p.RLock()
	session := p.session
	_ = session.CloseWithError(0, "")
	p.RUnlock()
}

// type check
var _ Upstream = &dnsOverQUIC{}

func (p *dnsOverQUIC) Address() string { return p.boot.URL.String() }

func (p *dnsOverQUIC) Exchange(m *dns.Msg) (*dns.Msg, error) {
	q := m.Question[0].String()
	log.Tracef("\n\033[34mStarting DoQ exchange for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
	log.Tracef("\nmetrics:DoQ exchange started for %s: %v\n", q, time.Now().Format(time.StampMilli))
	session, err := p.getSession(true)
	if err != nil {
		return nil, err
	}

	// If any message sent on a DoQ connection contains an edns-tcp-keepalive EDNS(0) Option,
	// this is a fatal error and the recipient of the defective message MUST forcibly abort
	// the connection immediately.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.6.2
	if opt := m.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				_ = session.CloseWithError(0, "") // Already closing the connection so we don't care about the error
				return nil, errors.New("EDNS0 TCP keepalive option is set")
			}
		}
	}

	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.4
	// When sending queries over a QUIC connection, the DNS Message ID MUST be set to zero.
	id := m.Id
	var reply *dns.Msg
	m.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies
		m.Id = id
		if reply != nil {
			reply.Id = id
		}
	}()

	stream, err := p.openStream(session)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to open new stream to %s", p.Address())
	}

	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}
	
	log.Tracef("\nmetrics:DoQ query send for %s: %v\n", q, time.Now().Format(time.StampMilli))
	_, err = stream.Write(buf)
	if err != nil {
		return nil, err
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// stream.Close() -- closes the write-direction of the stream.
	_ = stream.Close()

	pool := p.getBytesPool()
	bufPtr := pool.Get().(*[]byte)

	defer pool.Put(bufPtr)

	respBuf := *bufPtr
	n, err := stream.Read(respBuf)
	log.Tracef("\nmetrics:DoQ answer receive for %s: %v\n", q, time.Now().Format(time.StampMilli))
	if err != nil && n == 0 {
		return nil, errorx.Decorate(err, "failed to read response from %s due to %v", p.Address(), err)
	}

	reply = new(dns.Msg)
	err = reply.Unpack(respBuf)
	log.Tracef("\n\033[34mDoQ answer received for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
	if err != nil {
		return nil, errorx.Decorate(err, "failed to unpack response from %s", p.Address())
	}
	log.Tracef("\nmetrics:DoQ exchange finished for %s: %v\n", q, time.Now().Format(time.StampMilli))
	log.Tracef("\nmetrics:DoQ exchange for %s used 0-RTT: %t\n", q, session.ConnectionState().TLS.Used0RTT)

	return reply, nil
}

func (p *dnsOverQUIC) getBytesPool() *sync.Pool {
	p.Lock()
	if p.bytesPool == nil {
		p.bytesPool = &sync.Pool{
			New: func() interface{} {
				b := make([]byte, dns.MaxMsgSize)

				return &b
			},
		}
	}
	p.Unlock()
	return p.bytesPool
}

// getSession - opens or returns an existing quic.Session
// useCached - if true and cached session exists, return it right away
// otherwise - forcibly creates a new session
func (p *dnsOverQUIC) getSession(useCached bool) (quic.Session, error) {
	var session quic.Session

	p.RLock()
	session = p.session

	if session != nil && useCached {
		p.RUnlock()
		return session, nil
	}
	log.Tracef("\n\033[34mEstablishing new DoQ connection at: %v\n\033[0m", time.Now().Format(time.StampMilli))
	if session != nil {
		// we're recreating the session, let's create a new one
		_ = session.CloseWithError(0, "")
	}
	p.RUnlock()

	p.Lock()
	defer p.Unlock()

	var err error
	session, err = p.openSession()
	if err != nil {
		// This does not look too nice, but QUIC (or maybe quic-go)
		// doesn't seem stable enough.
		// Maybe retransmissions aren't fully implemented in quic-go?
		// Anyways, the simple solution is to make a second try when
		// it fails to open the QUIC session.
		session, err = p.openSession()
		if err != nil {
			return nil, err
		}
	}
	p.session = session
	log.Tracef("\n\033[34mEstablished new DoQ connection at: %v\n\033[0m", time.Now().Format(time.StampMilli))
	return session, nil
}

func (p *dnsOverQUIC) openStream(session quic.Session) (quic.Stream, error) {
	ctx := context.Background()

	if p.boot.options.Timeout > 0 {
		deadline := time.Now().Add(p.boot.options.Timeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel() // avoid resource leak
	}

	stream, err := session.OpenStreamSync(ctx)
	if err == nil {
		return stream, nil
	}

	// try to recreate the session
	newSession, err := p.getSession(false)
	if err != nil {
		return nil, err
	}
	// open a new stream
	return newSession.OpenStreamSync(ctx)
}

func (p *dnsOverQUIC) openSession() (quic.Session, error) {
	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, err
	}
	if tlsConfig.ClientSessionCache != nil {
		log.Tracef("\n---tls config has client session cache, handed through via bootstrapper\n")
	} else {
		log.Tracef("\n---tls config does not have client session cache, was not handed through via bootstrapper, setting from outer options\n")
	}
	
	if p.tokenStore != nil {
		log.Tracef("\n---token store of dnsOverQUIC is not nil\n")
	}
	
	log.Printf("---openSession: tokenStore: %s\n", p.tokenStore)
	log.Printf("---openSession: clientSessionCache: %s\n", tlsConfig.ClientSessionCache)

	// we're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there are v4/v6 addresses)
	rawConn, err := dialContext(context.TODO(), "udp", "")
	if err != nil {
		return nil, err
	}
	// It's never actually used
	_ = rawConn.Close()

	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed to open connection to %s", p.Address())
	}

	// Store version information
	versions := []quic.VersionNumber{quic.Version1, quic.VersionDraft34, quic.VersionDraft32, quic.VersionDraft29}
	version := p.version
	if version != 0x0 {
		versions = []quic.VersionNumber{version}
	}

	addr := udpConn.RemoteAddr().String()
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		Tracer: qlog.NewTracer(func(p logging.Perspective, connectionID []byte) io.WriteCloser {
			return newWriteCloser()
		}),
		TokenStore:     p.tokenStore,
		Versions:       versions,
		MaxIdleTimeout: time.Millisecond * 3000000,
	}
	log.Tracef("\nmetrics:DoQ QUIC handshake start: %v\n", time.Now().Format(time.StampMilli))

	session, versionInfo, err := quic.DialAddrEarlyContext(context.Background(), addr, tlsConfig, quicConfig, 40000)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to open QUIC session to %s", p.Address())
	}
	p.version = versionInfo.Version
	
	log.Tracef("\nmetrics:DoQ QUIC handshake done: %v\n", time.Now().Format(time.StampMilli))
	
	return session, nil
}
