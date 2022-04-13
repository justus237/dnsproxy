package upstream

import (
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

//
// plain DNS
//
type plainDNS struct {
	address   string
	timeout   time.Duration
	preferTCP bool
}

// type check
var _ Upstream = &plainDNS{}

// Address returns the original address that we've put in initially, not resolved one
func (p *plainDNS) Address() string {
	if p.preferTCP {
		return "tcp://" + p.address
	}
	return p.address
}

func (p *plainDNS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	q := m.Question[0].String()
	if p.preferTCP {
		log.Tracef("\n\033[34mStarting DoTCP exchange for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
		exchangeStart := time.Now()
		//log.Tracef("\nmetrics:DoTCP exchange started for [%s]: %v\n", q, exchangeStart.Format(time.StampMilli))
		tcpClient := dns.Client{Net: "tcp", Timeout: p.timeout}

		logBegin(p.Address(), m)
		reply, _, tcpErr := tcpClient.Exchange(m, p.address)
		exchangeFinished := time.Now()
		//log.Tracef("\nmetrics:DoTCP exchange finished for [%s]: %v\n", q, exchangeFinished.Format(time.StampMilli))
		log.Tracef("\n\033[34mDoTCP answer received for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
		log.Tracef("\nmetrics:DoTCP exchange duration for [%s] from %v to %v: %s\n", q, exchangeStart.Format(time.StampMilli), exchangeFinished.Format(time.StampMilli), exchangeFinished.Sub(exchangeStart))
		logFinish(p.Address(), tcpErr)
		return reply, tcpErr
	}

	client := dns.Client{Timeout: p.timeout, UDPSize: dns.MaxMsgSize}

	logBegin(p.Address(), m)
	log.Tracef("\n\033[34mStarting DoUDP exchange for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
	exchangeStart := time.Now()
	//log.Tracef("\nmetrics:DoUDP exchange started for [%s]: %v\n", q, exchangeStart.Format(time.StampMilli))
	reply, _, err := client.Exchange(m, p.address)
	exchangeFinished := time.Now()
	//log.Tracef("\nmetrics:DoUDP exchange finished for [%s]: %v\n", q, exchangeFinished.Format(time.StampMilli))
	log.Tracef("\n\033[34mDoUDP answer received for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
	//log.Tracef("\nmetrics:DoUDP exchange duration: %s\n", exchangeFinished.Sub(exchangeStart))
	log.Tracef("\nmetrics:DoUDP exchange duration for [%s] from %v to %v: %s\n", q, exchangeStart.Format(time.StampMilli), exchangeFinished.Format(time.StampMilli), exchangeFinished.Sub(exchangeStart))
	logFinish(p.Address(), err)

	if reply != nil && reply.Truncated {
		log.Tracef("Truncated message was received, retrying over TCP, question: %s", m.Question[0].String())
		log.Tracef("\n\033[34mStarting DoTCP exchange for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
		exchangeStart := time.Now()
		//log.Tracef("\nmetrics:DoTCP fallback exchange started for [%s]: %v\n", q, exchangeStart.Format(time.StampMilli))
		tcpClient := dns.Client{Net: "tcp", Timeout: p.timeout}
		logBegin(p.Address(), m)

		reply, _, err = tcpClient.Exchange(m, p.address)
		exchangeFinished := time.Now()
		//log.Tracef("\nmetrics:DoTCP fallback exchange finished for [%s]: %v\n", q, exchangeFinished.Format(time.StampMilli))
		log.Tracef("\n\033[34mDoTCP answer received for: %s at: %v\n\033[0m", q, time.Now().Format(time.StampMilli))
		//log.Tracef("\nmetrics:DoTCP fallback exchange duration: %s\n", exchangeFinished.Sub(exchangeStart))
		log.Tracef("\nmetrics:DoTCP fallback exchange duration for [%s] from %v to %v: %s\n", q, exchangeStart.Format(time.StampMilli), exchangeFinished.Format(time.StampMilli), exchangeFinished.Sub(exchangeStart))
		logFinish(p.Address(), err)
	}

	return reply, err
}

func (p *plainDNS) Reset() {
}
