package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/core"
)

func recordFrom(t *testing.T, svc *audit.Service, ip, ua string) audit.Event {
	t.Helper()
	e, err := svc.Record(context.Background(), action(func(e *audit.Event) {
		e.Outcome, e.IP, e.UserAgent = audit.OutcomeOK, ip, ua
	}))
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	return e
}

func TestIPModes(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cases := []struct {
		name string
		opts []audit.Option
		in   string
		want string
	}{
		{"keep", nil, "203.0.113.77", "203.0.113.77"},
		{"truncate v4", []audit.Option{audit.WithIPMode(audit.IPTruncate)}, "203.0.113.77", "203.0.113.0"},
		{"truncate v6", []audit.Option{audit.WithIPMode(audit.IPTruncate)}, "2001:db8:1:2:3:4:5:6", "2001:db8:1::"},
		{"truncate mapped v4", []audit.Option{audit.WithIPMode(audit.IPTruncate)}, "::ffff:203.0.113.77", "203.0.113.0"},
		{"truncate custom", []audit.Option{audit.WithIPMode(audit.IPTruncate), audit.WithIPTruncation(16, 32)}, "203.0.113.77", "203.0.0.0"},
		{"truncate garbage", []audit.Option{audit.WithIPMode(audit.IPTruncate)}, "not-an-ip", ""},
		{"drop", []audit.Option{audit.WithIPMode(audit.IPDrop)}, "203.0.113.77", ""},
		{"hash without key", []audit.Option{audit.WithIPMode(audit.IPHash)}, "203.0.113.77", ""},
	}
	for _, c := range cases {
		svc, _, _ := newService(t, c.opts...)
		if got := recordFrom(t, svc, c.in, "ua").IP; got != c.want {
			t.Errorf("%s: IP = %q, want %q", c.name, got, c.want)
		}
	}
	svc, _, _ := newService(t, audit.WithIPMode(audit.IPHash), audit.WithIPHashKey(key))
	a, b, c := recordFrom(t, svc, "203.0.113.77", ""), recordFrom(t, svc, "203.0.113.77", ""), recordFrom(t, svc, "203.0.113.78", "")
	if a.IP == "" || a.IP == "203.0.113.77" || a.IP != b.IP || a.IP == c.IP {
		t.Errorf("hashes = %q %q %q; want a stable, distinct, non-address value", a.IP, b.IP, c.IP)
	}
	svc, _, _ = newService(t, audit.WithoutUserAgent())
	if got := recordFrom(t, svc, "1.2.3.4", "curl/8").UserAgent; got != "" {
		t.Errorf("UserAgent = %q, want dropped", got)
	}
}

func TestClientDataRetentionClearsOnlyClientDataAndKeepsSealsValid(t *testing.T) {
	_, st, clk := newService(t)
	svc := audit.New(st, audit.WithRuntime(core.Runtime{Clock: clk.Now}),
		audit.WithTopics(audit.Topic{Key: "menus", ClientDataRetention: 7 * 24 * time.Hour}))
	ctx := context.Background()
	clk.Set(day(1).Add(time.Hour))
	old := recordFrom(t, svc, "203.0.113.7", "agent/1")
	clk.Set(day(10).Add(time.Hour))
	fresh := recordFrom(t, svc, "203.0.113.8", "agent/2")

	clk.Set(day(12))
	if _, err := svc.Seal(ctx, day(2)); err != nil {
		t.Fatal(err)
	}
	cleared, err := svc.ScrubClientData(ctx)
	if err != nil || cleared["menus"] != 1 {
		t.Fatalf("ScrubClientData = %v, %v; want 1 cleared", cleared, err)
	}
	gotOld, _ := svc.Get(ctx, old.ID)
	gotFresh, _ := svc.Get(ctx, fresh.ID)
	if gotOld.IP != "" || gotOld.UserAgent != "" || gotOld.Action != old.Action || gotOld.Seq != old.Seq {
		t.Errorf("old event = %+v", gotOld)
	}
	if gotFresh.IP != "203.0.113.8" || gotFresh.UserAgent != "agent/2" {
		t.Errorf("fresh event lost its client data: %+v", gotFresh)
	}
	sts, err := svc.Verify(ctx, []string{"menus"}, day(1), day(1))
	if err != nil || sts[0].State != audit.DayOK {
		t.Fatalf("Verify after scrub = %+v, %v; want ok: client data is outside the seal", sts, err)
	}
}
