package audit_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bernardoforcillo/authlayer/audit"
)

func redact(t *testing.T, in string, p audit.Policy) string {
	t.Helper()
	return string(audit.Redact(json.RawMessage(in), p))
}

func TestRedactRemovesSecretsByWord(t *testing.T) {
	in := `{"user":{"newPassword":"p","name":"Ann"},"api_key":"k","apiKey":"k",
		"X-API-KEY":"k","refreshToken":"t","tokens":["a"],"client_secret":"s",
		"OTPCode":"1","recovery_codes":["c"],"Authorization":"Bearer x",
		"footprint":12,"tokenizer":"keep","secretary":"keep",
		"password1":"s","password2":"s","Password2":"s","token1":"s","secret2":"s",
		"otp1":"s","refresh_token2":"s","apikey":"s","APIKEY":"s","privatekey":"s",
		"PRIVATEKEY":"s","recoverycode":"s"}`
	want := `{"user":{"newPassword":"[REDACTED]","name":"Ann"},"api_key":"[REDACTED]",
		"apiKey":"[REDACTED]","X-API-KEY":"[REDACTED]","refreshToken":"[REDACTED]",
		"tokens":"[REDACTED]","client_secret":"[REDACTED]","OTPCode":"[REDACTED]",
		"recovery_codes":"[REDACTED]","Authorization":"[REDACTED]","footprint":12,
		"tokenizer":"keep","secretary":"keep",
		"password1":"[REDACTED]","password2":"[REDACTED]","Password2":"[REDACTED]",
		"token1":"[REDACTED]","secret2":"[REDACTED]","otp1":"[REDACTED]",
		"refresh_token2":"[REDACTED]","apikey":"[REDACTED]","APIKEY":"[REDACTED]",
		"privatekey":"[REDACTED]","PRIVATEKEY":"[REDACTED]","recoverycode":"[REDACTED]"}`
	if got := redact(t, in, audit.DefaultPolicy()); !audit.EqualJSON(json.RawMessage(got), json.RawMessage(want)) {
		t.Errorf("Redact =\n%s\nwant\n%s", got, want)
	}
}

func TestRedactMasksEveryStringUnderAMaskedKey(t *testing.T) {
	p := audit.DefaultPolicy()
	p.Mask = append(p.Mask, "phone")
	in := `{"email":"bernardo@example.com","inviteeEmails":["a@b.it","cc@d.it"],
		"contact":{"phone":"+39 333 1234567"},"emailVerified":true,"note":"x"}`
	want := `{"email":"b***@example.com","inviteeEmails":["a***@b.it","c***@d.it"],
		"contact":{"phone":"***4567"},"emailVerified":true,"note":"x"}`
	if got := redact(t, in, p); !audit.EqualJSON(json.RawMessage(got), json.RawMessage(want)) {
		t.Errorf("Redact =\n%s\nwant\n%s", got, want)
	}
}

func TestRedactTruncatesLongStrings(t *testing.T) {
	long := strings.Repeat("a", 2000)
	got := redact(t, `{"blob":"`+long+`"}`, audit.DefaultPolicy())
	var v struct {
		Blob struct {
			Truncated bool   `json:"truncated"`
			Len       int    `json:"len"`
			SHA256    string `json:"sha256"`
		} `json:"blob"`
	}
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Fatalf("unmarshal %s: %v", got, err)
	}
	if !v.Blob.Truncated || v.Blob.Len != 2000 || len(v.Blob.SHA256) != 64 {
		t.Errorf("blob = %+v, want a truncation summary", v.Blob)
	}
}

func TestRedactCapsTheWholePayload(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"rows":[`)
	for i := 0; i < 5000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"row-value-0123456789"`)
	}
	b.WriteString(`]}`)
	got := audit.Redact(json.RawMessage(b.String()), audit.DefaultPolicy())
	if len(got) > 200 || !strings.Contains(string(got), `"truncated":true`) {
		t.Errorf("Redact of a %d-byte payload = %d bytes: %s", b.Len(), len(got), got)
	}
}

func TestRedactEdgeCases(t *testing.T) {
	if got := audit.Redact(nil, audit.DefaultPolicy()); got != nil {
		t.Errorf("Redact(nil) = %s, want nil", got)
	}
	if got := redact(t, `not json`, audit.DefaultPolicy()); got != `{"redaction_error":true}` {
		t.Errorf("Redact(not json) = %s", got)
	}
	if got := redact(t, `{"n":12345678901234567890}`, audit.DefaultPolicy()); got != `{"n":12345678901234567890}` {
		t.Errorf("Redact changed a number: %s", got)
	}
}

func TestDefaultPolicyRemovesTheCommonSecretShapes(t *testing.T) {
	secrets := []string{"totp", "mfa_code", "mfaCode", "passphrase", "pwd", "jwt", "pin", "signing_key", "signingKey",
		"access_key", "accessKey", "AWS_ACCESS_KEY", "code_verifier", "codeVerifier", "pass", "plaintext", "bearer",
		"device_code", "user_code", "encryption_key", "hmac_key", "master_key", "session_key", "smtp_pass"}
	kept := []string{"footprint", "tokenizer", "secretary", "sha256", "role_key", "key", "code", "pinned",
		"passenger", "compass", "error_code", "session_id", "spinner"}
	in := map[string]string{}
	for _, k := range append(append([]string{}, secrets...), kept...) {
		in[k] = "v"
	}
	raw, _ := json.Marshal(in)
	var out map[string]string
	if err := json.Unmarshal(audit.Redact(raw, audit.DefaultPolicy()), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range secrets {
		if out[k] != audit.Redacted {
			t.Errorf("%s = %q, want redacted", k, out[k])
		}
	}
	for _, k := range kept {
		if out[k] != "v" {
			t.Errorf("%s = %q, want kept", k, out[k])
		}
	}
}

func TestRedactionErrorIsAFreshCopy(t *testing.T) {
	first := audit.Redact(json.RawMessage(`not json`), audit.DefaultPolicy())
	for i := range first {
		first[i] = 'x'
	}
	if got := string(audit.Redact(json.RawMessage(`not json`), audit.DefaultPolicy())); got != `{"redaction_error":true}` {
		t.Errorf("Redact after a caller mutated an earlier result = %s", got)
	}
}
