package upstream

import (
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/joomcode/errorx"
	"github.com/miekg/dns"
)

//
// DNS-over-TLS
//
type dnsOverTLS struct {
	boot *bootstrapper
	pool *TLSPool

	sync.RWMutex // protects pool
}

// type check
var _ Upstream = &dnsOverTLS{}

func (p *dnsOverTLS) Address() string { return p.boot.URL.String() }

func (p *dnsOverTLS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	q := m.Question[0].String()
	exchangeStart := time.Now()
	//log.Tracef("\nmetrics:DoT exchange started for %s: %v\n", q, exchangeStart.Format(time.StampMilli))
	var pool *TLSPool
	p.RLock()
	pool = p.pool
	p.RUnlock()
	if pool == nil {
		p.Lock()
		// lazy initialize it
		p.pool = &TLSPool{boot: p.boot}
		p.Unlock()
	}

	log.Tracef("\n\033[34mStarting DoT exchange for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
	p.RLock()
	poolConn, err := p.pool.Get()
	p.RUnlock()
	if err != nil {
		return nil, errorx.Decorate(err, "Failed to get a connection from TLSPool to %s", p.Address())
	}

	logBegin(p.Address(), m)
	reply, err := p.exchangeConn(poolConn, m)
	log.Tracef("\n\033[34mDoT answer received for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
	logFinish(p.Address(), err)
	if err != nil {
		log.Tracef("The TLS connection is expired due to %s", err)

		// The pooled connection might have been closed already (see https://github.com/AdguardTeam/dnsproxy/issues/3)
		// So we're trying to re-connect right away here.
		// We are forcing creation of a new connection instead of calling Get() again
		// as there's no guarantee that other pooled connections are intact
		p.RLock()
		poolConn, err = p.pool.Create()
		p.RUnlock()
		if err != nil {
			return nil, errorx.Decorate(err, "Failed to create a new connection from TLSPool to %s", p.Address())
		}

		// Retry sending the DNS request
		logBegin(p.Address(), m)
		log.Tracef("\n\033[34mSending DoT query: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
		reply, err = p.exchangeConn(poolConn, m)
		log.Tracef("\n\033[34mDoT answer received for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
		logFinish(p.Address(), err)

	}
	p.RLock()
	if err == nil && p.pool != nil {
		p.pool.Put(poolConn)
	}
	p.RUnlock()
	exchangeFinished := time.Now()
	//log.Tracef("\nmetrics:DoT exchange finished for %s: %v\n", q, exchangeFinished.Format(time.StampMilli))
	//log.Tracef("\nmetrics:DoT exchange duration: %s\n", exchangeFinished.Sub(exchangeStart))
	log.Tracef("\nmetrics:DoT exchange duration for [%s] from %v to %v: %s\n", q, exchangeStart.Format(time.StampMilli), exchangeFinished.Format(time.StampMilli), exchangeFinished.Sub(exchangeStart))
	return reply, err
}

func (p *dnsOverTLS) Reset() {
	p.RLock()
	p.pool = nil
	p.RUnlock()
}

func (p *dnsOverTLS) exchangeConn(poolConn net.Conn, m *dns.Msg) (*dns.Msg, error) {
	c := dns.Conn{Conn: poolConn}
	q := m.Question[0].String()
	querySend := time.Now()
	//log.Tracef("\nmetrics:DoT query send for %s: %v\n", q, querySend.Format(time.StampMilli))
	err := c.WriteMsg(m)
	if err != nil {
		poolConn.Close()
		return nil, errorx.Decorate(err, "Failed to send a request to %s", p.Address())
	}

	reply, err := c.ReadMsg()
	answerReceive := time.Now()
	//log.Tracef("\nmetrics:DoT answer receive for %s: %v\n", q, answerReceive.Format(time.StampMilli))
	//log.Tracef("\nmetrics:DoT query duration: %s\n", answerReceive.Sub(querySend))
	log.Tracef("\nmetrics:DoT query duration for [%s] from %v to %v: %s\n", q, querySend.Format(time.StampMilli), answerReceive.Format(time.StampMilli), answerReceive.Sub(querySend))
	if err != nil {
		poolConn.Close()
		return nil, errorx.Decorate(err, "Failed to read a request from %s", p.Address())
	} else if reply.Id != m.Id {
		err = dns.ErrId
	}

	return reply, err
}
