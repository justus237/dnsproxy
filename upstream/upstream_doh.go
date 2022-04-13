package upstream

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"

	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Values to configure HTTP and HTTP/2 transport.
const (
	// transportDefaultReadIdleTimeout is the default timeout for pinging
	// idle connections in HTTP/2 transport.
	transportDefaultReadIdleTimeout = 30 * time.Second

	// transportDefaultIdleConnTimeout is the default timeout for idle
	// connections in HTTP transport.
	transportDefaultIdleConnTimeout = 5 * time.Minute

	// dohMaxConnsPerHost controls the maximum number of connections for
	// each host.
	dohMaxConnsPerHost = 1

	// dohMaxIdleConns controls the maximum number of connections being idle
	// at the same time.
	dohMaxIdleConns = 1
)

// dnsOverHTTPS represents DNS-over-HTTPS upstream.
type dnsOverHTTPS struct {
	boot *bootstrapper

	// The Client's Transport typically has internal state (cached TCP
	// connections), so Clients should be reused instead of created as
	// needed. Clients are safe for concurrent use by multiple goroutines.
	client      *http.Client
	clientGuard sync.Mutex
}

// type check
var _ Upstream = &dnsOverHTTPS{}

func (p *dnsOverHTTPS) Address() string { return p.boot.URL.String() }

func (p *dnsOverHTTPS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	q := m.Question[0].String()
	log.Tracef("\n\033[34mStarting DoH exchange for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
	exchangeStart := time.Now()
	//log.Tracef("\nmetrics:DoH exchange started for %s: %v\n", q, exchangeStart.Format(time.StampMilli))
	//cannot really log handshake time due to lazy initialization...
	/*handshakeStart := time.Now()
	log.Tracef("\nmetrics:DoH transport configuration start: %v\n", handshakeStart.Format(time.StampMilli))*/
	client, err := p.getClient()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't initialize HTTP client or transport")
	}
	/*handshakeDone := time.Now()
	log.Tracef("\nmetrics:DoH transport configuration finished: %v\n", handshakeDone.Format(time.StampMilli))
	log.Tracef("\nmetrics:DoH transport configuration duration: %s\n", handshakeDone.Sub(handshakeStart))*/

	logBegin(p.Address(), m)
	r, err := p.exchangeHTTPSClient(m, client)
	log.Tracef("\n\033[34mDoH answer received for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
	logFinish(p.Address(), err)
	exchangeFinished := time.Now()
	//log.Tracef("\nmetrics:DoH exchange finished for %s: %v\n", q, exchangeFinished.Format(time.StampMilli))
	//log.Tracef("\nmetrics:DoH exchange duration: %s\n", exchangeFinished.Sub(exchangeStart))
	log.Tracef("\nmetrics:DoH exchange duration for [%s] from %v to %v: %s\n", q, exchangeStart.Format(time.StampMilli), exchangeFinished.Format(time.StampMilli), exchangeFinished.Sub(exchangeStart))

	return r, err
}

func (p *dnsOverHTTPS) Reset() {
	p.clientGuard.Lock()
	p.client = nil
	p.clientGuard.Unlock()
}

// exchangeHTTPSClient sends the DNS query to a DOH resolver using the specified
// http.Client instance.
func (p *dnsOverHTTPS) exchangeHTTPSClient(m *dns.Msg, client *http.Client) (*dns.Msg, error) {
	q := m.Question[0].String()
	buf, err := m.Pack()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't pack request msg")
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	requestURL := p.Address() + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't create a HTTP request to %s", p.boot.URL)
	}
	req.Header.Set("Accept", "application/dns-message")

	querySend := time.Now()
	//log.Tracef("\nmetrics:DoH query send for %s: %v\n", q, querySend.Format(time.StampMilli))
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// TODO: consider using errors.As
		if os.IsTimeout(err) {
			// If this is a timeout error, trying to forcibly re-create the HTTP client instance
			// See https://github.com/AdguardTeam/AdGuardHome/issues/3217 for more details on this
			p.clientGuard.Lock()
			p.client = nil
			p.clientGuard.Unlock()
		}
		//log.Tracef("\nmetrics:DoH answer timeout for %s: %v\n", q, time.Now().Format(time.StampMilli))
		return nil, errorx.Decorate(err, "couldn't do a GET request to '%s'", p.boot.URL)
	}

	body, err := ioutil.ReadAll(resp.Body)
	answerReceive := time.Now()
	//log.Tracef("\nmetrics:DoH answer receive for %s: %v\n", q, answerReceive.Format(time.StampMilli))
	//log.Tracef("\nmetrics:DoH query (and likely handshake) duration: %s\n", answerReceive.Sub(querySend))
	log.Tracef("\nmetrics:DoH query (and likely handshake) duration for [%s] from %v to %v: %s\n", q, querySend.Format(time.StampMilli), answerReceive.Format(time.StampMilli), answerReceive.Sub(querySend))
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't read body contents for '%s'", p.boot.URL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got an unexpected HTTP status code %d from '%s'", resp.StatusCode, p.boot.URL)
	}
	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't unpack DNS response from '%s': body is %s", p.boot.URL, string(body))
	}
	if response.Id != m.Id {
		err = dns.ErrId
	}
	return &response, err
}

// getClient gets or lazily initializes an HTTP client (and transport) that will
// be used for this DOH resolver.
func (p *dnsOverHTTPS) getClient() (c *http.Client, err error) {
	startTime := time.Now()

	p.clientGuard.Lock()
	defer p.clientGuard.Unlock()

	if p.client != nil {
		return p.client, nil
	}

	// Timeout can be exceeded while waiting for the lock
	// This happens quite often on mobile devices
	elapsed := time.Since(startTime)
	if p.boot.options.Timeout > 0 && elapsed > p.boot.options.Timeout {
		return nil, fmt.Errorf("timeout exceeded: %s", elapsed)
	}

	p.client, err = p.createClient()

	return p.client, err
}

func (p *dnsOverHTTPS) createClient() (*http.Client, error) {
	transport, err := p.createTransport()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't initialize HTTP transport")
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   p.boot.options.Timeout,
		Jar:       nil,
	}

	p.client = client
	return p.client, nil
}

// createTransport initializes an HTTP transport that will be used specifically
// for this DOH resolver. This HTTP transport ensures that the HTTP requests
// will be sent exactly to the IP address got from the bootstrap resolver.
func (p *dnsOverHTTPS) createTransport() (*http.Transport, error) {
	tlsConfig, dialContext, err := p.boot.get()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't bootstrap %s", p.boot.URL)
	}

	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		DialContext:        dialContext,
		IdleConnTimeout:    transportDefaultIdleConnTimeout,
		MaxConnsPerHost:    dohMaxConnsPerHost,
		MaxIdleConns:       dohMaxIdleConns,
		// Since we have a custom DialContext, we need to use this field to
		// make golang http.Client attempt to use HTTP/2. Otherwise, it would
		// only be used when negotiated on the TLS level.
		ForceAttemptHTTP2: true,
	}

	// Explicitly configure transport to use HTTP/2.
	//
	// See https://github.com/AdguardTeam/dnsproxy/issues/11.
	var transportH2 *http2.Transport
	transportH2, err = http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	// Enable HTTP/2 pings on idle connections.
	transportH2.ReadIdleTimeout = transportDefaultReadIdleTimeout

	return transport, nil
}
