package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// IPMode says what the Service stores of an event's IP address. An IP address
// is personal data under the GDPR, so the default is to keep only as much as
// the purpose needs.
type IPMode int

const (
	// IPKeep stores the address as given. It is the zero value, so a Service
	// built without [WithIPMode] changes nothing.
	IPKeep IPMode = iota
	// IPTruncate zeroes the host part: an IPv4 address keeps its /24, an
	// IPv6 address its /48 ([WithIPTruncation] changes the widths). The
	// result is still useful to spot a country or a network, and no longer
	// names a household.
	IPTruncate
	// IPHash stores a keyed hash of the address ([WithIPHashKey]): events
	// from the same address still correlate, the address itself is gone, and
	// without the key it cannot be recovered by trying every IPv4 address.
	IPHash
	// IPDrop stores nothing.
	IPDrop
)

type clientConfig struct {
	ip        IPMode
	v4, v6    int
	hashKey   []byte
	dropAgent bool
}

// WithIPMode sets what the Service stores of the IP address of every event it
// records. An address that does not parse is dropped under every mode but
// IPKeep rather than stored half-minimized. IPHash needs [WithIPHashKey].
func WithIPMode(m IPMode) Option { return func(c *config) { c.client.ip = m } }

// WithIPTruncation sets the prefix lengths IPTruncate keeps, 24 and 48 by
// default. Values outside 0..32 and 0..128 keep the default.
func WithIPTruncation(v4, v6 int) Option {
	return func(c *config) {
		if v4 >= 0 && v4 <= 32 {
			c.client.v4 = v4
		}
		if v6 >= 0 && v6 <= 128 {
			c.client.v6 = v6
		}
	}
}

// WithIPHashKey is the HMAC key of IPMode IPHash. Keep it secret and stable:
// rotating it breaks correlation with older events, and destroying it makes
// the stored hashes unlinkable to any address.
func WithIPHashKey(key []byte) Option {
	return func(c *config) { c.client.hashKey = append([]byte(nil), key...) }
}

// WithoutUserAgent stops the Service from storing the user agent of events.
func WithoutUserAgent() Option { return func(c *config) { c.client.dropAgent = true } }

func (c clientConfig) minimizeIP(raw string) string {
	if raw == "" || c.ip == IPKeep {
		return raw
	}
	if c.ip == IPDrop {
		return ""
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	addr = addr.Unmap().WithZone("")
	switch c.ip {
	case IPTruncate:
		bits := c.v6
		if addr.Is4() {
			bits = c.v4
		}
		p, err := addr.Prefix(bits)
		if err != nil {
			return ""
		}
		return p.Masked().Addr().String()
	case IPHash:
		if len(c.hashKey) == 0 {
			return ""
		}
		m := hmac.New(sha256.New, c.hashKey)
		m.Write(addr.AsSlice())
		return "h:" + hex.EncodeToString(m.Sum(nil))[:32]
	}
	return ""
}

// minimize applies the configured client-data policy to an event about to be
// stored.
func (s *Service) minimizeClient(e *Event) {
	e.IP = s.cfg.client.minimizeIP(e.IP)
	if s.cfg.client.dropAgent {
		e.UserAgent = ""
	}
}

func (s *Service) clientRetention(key string) time.Duration {
	if r := s.cfg.topics[key].ClientDataRetention; r > 0 {
		return r
	}
	return 0
}

// ScrubClientData clears the IP address and user agent of events older than
// their topic's ClientDataRetention, keeping the events, and returns how many
// events it cleared per topic. Topics without a ClientDataRetention are left
// alone. It touches no hashed field, so seals stay valid; it is also part of
// [Service.ApplyRetention].
func (s *Service) ScrubClientData(ctx context.Context) (map[string]int, error) {
	now := s.now()
	cleared := map[string]int{}
	var errs []error
	for _, topic := range s.keys {
		keep := s.clientRetention(topic)
		if keep == 0 {
			continue
		}
		before := now.Add(-keep)
		for {
			n, err := s.store.ScrubClientData(ctx, topic, before, maintainBatch)
			cleared[topic] += n
			if err != nil {
				errs = append(errs, fmt.Errorf("scrub %s: %w", topic, err))
				break
			}
			if n < maintainBatch {
				break
			}
		}
	}
	return cleared, errors.Join(errs...)
}
