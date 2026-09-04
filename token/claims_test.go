package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// The pre-existing payload must be byte-identical when none of the new
// claims is set: the token an HS256 deployment mints today must not change
// shape because fields were added to Claims. The header is pinned too, since
// jwtHeader gained an omitempty kid at the same time.
func TestClaimsPayloadUnchangedWhenNewFieldsUnset(t *testing.T) {
	c := sampleClaims()
	c.IssuedAt = 1_700_000_000
	c.ExpiresAt = 1_700_000_900
	got, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"sub":"user-123","sid":"session-456","email":"alice@example.com","iat":1700000000,"exp":1700000900}`
	if string(got) != want {
		t.Fatalf("payload =\n%s\nwant\n%s", got, want)
	}

	raw, err := Issue(sampleClaims(), keyA, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	header, err := base64.RawURLEncoding.Strict().DecodeString(strings.Split(raw, ".")[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if string(header) != `{"alg":"HS256","typ":"JWT"}` {
		t.Fatalf("HS256 header = %s, want it unchanged with no kid", header)
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(strings.Split(raw, ".")[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	for _, key := range []string{`"iss"`, `"aud"`, `"jti"`, `"client_id"`, `"scope"`, `"act"`, `"ext"`} {
		if strings.Contains(string(payload), key) {
			t.Fatalf("payload %s contains %s although it was never set", payload, key)
		}
	}
}

// When set, the new claims round-trip through both signers with their RFC
// names, in struct order, and Actor nests as an object.
func TestClaimsNewFieldsRoundTrip(t *testing.T) {
	c := sampleClaims()
	c.Issuer = "https://issuer.example"
	c.Audience = Audience{"https://api.example"}
	c.ID = "jti-1"
	c.ClientID = "client-1"
	c.Scope = "read write"
	c.Actor = &Actor{Subject: "sa-1", ClientID: "client-2"}
	c.IssuedAt, c.ExpiresAt = 1, 2

	got, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"sub":"user-123","sid":"session-456","email":"alice@example.com","iat":1,"exp":2,` +
		`"iss":"https://issuer.example","aud":"https://api.example","jti":"jti-1",` +
		`"client_id":"client-1","scope":"read write","act":{"sub":"sa-1","client_id":"client-2"}}`
	if string(got) != want {
		t.Fatalf("payload =\n%s\nwant\n%s", got, want)
	}

	hs, _ := HS256(keyA)
	ed, _ := newEdDSA(t, "k1", nil)
	for name, s := range map[string]Signer{"HS256": hs, "EdDSA": ed} {
		raw, err := s.Issue(c, time.Hour)
		if err != nil {
			t.Fatalf("%s.Issue: %v", name, err)
		}
		back, err := s.Parse(raw)
		if err != nil {
			t.Fatalf("%s.Parse: %v", name, err)
		}
		if back.Issuer != c.Issuer || back.ID != c.ID || back.ClientID != c.ClientID || back.Scope != c.Scope {
			t.Fatalf("%s: scalar claims did not round-trip: %+v", name, back)
		}
		if len(back.Audience) != 1 || back.Audience[0] != "https://api.example" {
			t.Fatalf("%s: Audience = %v, want [https://api.example]", name, back.Audience)
		}
		if back.Actor == nil || *back.Actor != *c.Actor {
			t.Fatalf("%s: Actor = %+v, want %+v", name, back.Actor, c.Actor)
		}
	}
}

// Audience writes a bare string for one recipient and an array otherwise,
// reads both forms and null, and refuses anything else.
func TestAudienceEncoding(t *testing.T) {
	one, _ := json.Marshal(Audience{"a"})
	if string(one) != `"a"` {
		t.Fatalf("one audience = %s, want \"a\"", one)
	}
	two, _ := json.Marshal(Audience{"a", "b"})
	if string(two) != `["a","b"]` {
		t.Fatalf("two audiences = %s, want [\"a\",\"b\"]", two)
	}

	type wrap struct {
		Aud Audience `json:"aud,omitempty"`
	}
	empty, _ := json.Marshal(wrap{})
	if string(empty) != `{}` {
		t.Fatalf("empty Audience with omitempty = %s, want {}", empty)
	}

	for in, want := range map[string]Audience{
		`{"aud":"a"}`:               {"a"},
		`{"aud":["a","b"]}`:         {"a", "b"},
		`{"aud":[]}`:                {},
		`{"aud":null}`:              nil,
		`{}`:                        nil,
		`{"aud":"https://x/y?z=1"}`: {"https://x/y?z=1"},
	} {
		var w wrap
		if err := json.Unmarshal([]byte(in), &w); err != nil {
			t.Fatalf("unmarshal %s: %v", in, err)
		}
		if len(w.Aud) != len(want) {
			t.Fatalf("unmarshal %s = %v, want %v", in, w.Aud, want)
		}
		for i := range want {
			if w.Aud[i] != want[i] {
				t.Fatalf("unmarshal %s = %v, want %v", in, w.Aud, want)
			}
		}
	}
	for _, in := range []string{`{"aud":1}`, `{"aud":{"x":1}}`, `{"aud":["a",1]}`, `{"aud":true}`} {
		var w wrap
		if err := json.Unmarshal([]byte(in), &w); err == nil {
			t.Fatalf("unmarshal %s succeeded, want an error", in)
		}
	}

	if !(Audience{"a", "b"}).Contains("b") || (Audience{"a"}).Contains("b") || (Audience(nil)).Contains("") {
		t.Fatal("Contains gave a wrong answer")
	}
}

// A payload whose aud is not a string or array reaches Parse as
// ErrMalformedToken, through the same path any other non-decodable payload
// takes — after the signature has verified, so the shape of a forged aud
// cannot be probed without the key.
func TestParseRejectsMalformedAudienceAsMalformedToken(t *testing.T) {
	headerJSON := `{"alg":"HS256","typ":"JWT"}`
	payloadJSON := `{"sub":"u","sid":"s","email":"e","iat":1,"exp":9999999999,"aud":{"not":"valid"}}`
	signingInput := rawURL([]byte(headerJSON)) + "." + rawURL([]byte(payloadJSON))
	raw := signingInput + "." + rawURL(signHS256(keyA, signingInput))
	if _, err := Parse(raw, keyA); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("Parse(object aud) = %v, want ErrMalformedToken", err)
	}
	// The same token under the wrong key is an invalid signature, not a
	// malformed token: the payload is never decoded before verification.
	if _, err := Parse(raw, keyB); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Parse(object aud, wrong key) = %v, want ErrInvalidSignature", err)
	}
}
