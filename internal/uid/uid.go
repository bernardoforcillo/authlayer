// Package uid generates RFC 9562 UUIDv7 identifiers.
//
// v7 puts a 48-bit big-endian Unix millisecond timestamp in the leading bytes,
// so ids sort in creation order and a b-tree index on a UUID primary key stays
// dense — the property v4 lacks and the reason authlayer defaults to v7.
//
// It exists so authlayer needs no UUID dependency; the whole generator is one
// crypto/rand read and some bit twiddling.
package uid

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewV7 returns a UUIDv7 in canonical 8-4-4-4-12 hyphenated form.
//
// 74 bits are random: 12 in the block following the version nibble and 62
// following the variant bits. A crypto/rand failure panics rather than
// degrading to predictable ids — an id generator that silently weakens is worse
// than one that stops the process at startup.
func NewV7() string {
	var b [16]byte

	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)

	if _, err := rand.Read(b[6:]); err != nil {
		panic("authlayer/internal/uid: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 0b10 (RFC 4122/9562)

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}
