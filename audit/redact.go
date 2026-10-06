package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Redacted is the value of every field a [Policy] removes.
const Redacted = "[REDACTED]"

// redactionError is what Redact and Diff return for input they cannot read,
// so a recorder never fails on a payload it was handed. Each call returns its
// own copy, so a caller editing one cannot change the next.
func redactionError() json.RawMessage { return json.RawMessage(`{"redaction_error":true}`) }

// Policy says what [Redact] removes, masks and truncates.
//
// Patterns match JSON object keys by words. Keys and patterns are split on
// separators, camelCase and digit boundaries ("newPassword" is "new password",
// "password2" is "password 2", "X-API-KEY" is "x api key"), and a pattern
// matches a key whose words contain the pattern's words in a row, each equal
// or followed by a plural "s". Multi-word patterns also match the words
// written together without separators. So "token" matches "refreshToken" and
// "tokens", "api_key" matches "apiKey", "X-API-KEY", and "apikey", and "otp"
// matches "OTPCode" but not "footprint".
type Policy struct {
	// Remove patterns replace the whole value with Redacted, whatever its
	// type.
	Remove []string
	// Mask patterns mask every string under the key: an email keeps its
	// first character and its domain ("b***@example.com"), anything else its
	// last four characters ("***4567").
	Mask []string
	// MaxString replaces longer strings with {"truncated":true,"len":n,
	// "sha256":"…"}. Zero or less disables it.
	MaxString int
	// MaxBytes replaces a whole redacted payload longer than this with the
	// same summary. Zero or less disables it.
	MaxBytes int
}

// DefaultPolicy removes the usual secrets, masks emails, and truncates
// strings over 1 KiB and payloads over 16 KiB.
//
// Only keys are matched: a secret stored under a key that does not look like
// one — the value of a {"name":"Authorization","value":"…"} pair, or JSON
// embedded in a string — passes through. Redact such payloads yourself, or
// add their keys to the policy.
func DefaultPolicy() Policy {
	return Policy{
		Remove: []string{
			"password", "passwd", "pwd", "pass", "passphrase", "secret", "token", "jwt", "bearer",
			"api_key", "private_key", "signing_key", "access_key", "encryption_key", "hmac_key",
			"master_key", "session_key", "credential", "otp", "totp", "mfa_code", "pin",
			"recovery_code", "device_code", "user_code", "code_verifier", "cookie",
			"authorization", "plaintext",
		},
		Mask:      []string{"email"},
		MaxString: 1024,
		MaxBytes:  16384,
	}
}

// Redact returns raw with p applied. Empty input returns nil; input that is
// not a single JSON value returns {"redaction_error":true}. Numbers keep the
// form they were written in.
func Redact(raw json.RawMessage, p Policy) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	v, err := decodeJSON(raw)
	if err != nil {
		return redactionError()
	}
	r := redactor{remove: compile(p.Remove), mask: compile(p.Mask), maxString: p.MaxString}
	out, err := json.Marshal(r.value(v, false))
	if err != nil {
		return redactionError()
	}
	if p.MaxBytes > 0 && len(out) > p.MaxBytes {
		capped, err := json.Marshal(summary(out))
		if err != nil {
			return redactionError()
		}
		return capped
	}
	return out
}

type redactor struct {
	remove, mask [][]string
	maxString    int
}

func (r redactor) value(v any, masking bool) any {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			words := keyWords(k)
			switch {
			case matches(words, r.remove):
				x[k] = Redacted
			case matches(words, r.mask):
				x[k] = r.value(child, true)
			default:
				x[k] = r.value(child, masking)
			}
		}
		return x
	case []any:
		for i, child := range x {
			x[i] = r.value(child, masking)
		}
		return x
	case string:
		if masking {
			return maskString(x)
		}
		if r.maxString > 0 && len(x) > r.maxString {
			return summary([]byte(x))
		}
		return x
	}
	return v
}

// summary stands in for content too long to keep.
func summary(b []byte) map[string]any {
	sum := sha256.Sum256(b)
	return map[string]any{"truncated": true, "len": len(b), "sha256": hex.EncodeToString(sum[:])}
}

func compile(patterns []string) [][]string {
	out := make([][]string, 0, len(patterns)*2)
	for _, p := range patterns {
		if w := keyWords(p); len(w) > 0 {
			out = append(out, w)
			// Multi-word patterns also match when words are joined together.
			if len(w) > 1 {
				joined := strings.Join(w, "")
				out = append(out, []string{joined})
			}
		}
	}
	return out
}

func matches(words []string, patterns [][]string) bool {
	for _, p := range patterns {
		if containsRun(words, p) {
			return true
		}
	}
	return false
}

// containsRun reports whether pattern's words appear in words in a row, each
// equal or plural.
func containsRun(words, pattern []string) bool {
	for i := 0; i+len(pattern) <= len(words); i++ {
		ok := true
		for j, pw := range pattern {
			if w := words[i+j]; w != pw && w != pw+"s" {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// keyWords splits a key into lower-case words on non-alphanumerics, camelCase
// and digit-letter boundaries: "newPassword" → [new password], "password2" →
// [password 2], "APIKey" → [api key].
func keyWords(key string) []string {
	runes := []rune(key)
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if unicode.IsUpper(r) && len(cur) > 0 {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || nextLower {
				flush()
			}
		}
		if i > 0 {
			prev := runes[i-1]
			if unicode.IsDigit(r) != unicode.IsDigit(prev) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return words
}

func maskString(s string) string {
	if at := strings.LastIndex(s, "@"); at >= 0 {
		local, domain := s[:at], s[at+1:]
		if local == "" {
			return "***@" + domain
		}
		r, _ := utf8.DecodeRuneInString(local)
		return string(r) + "***@" + domain
	}
	runes := []rune(s)
	if len(runes) <= 4 {
		return "****"
	}
	return "***" + string(runes[len(runes)-4:])
}
