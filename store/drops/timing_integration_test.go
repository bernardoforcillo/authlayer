//go:build integration

// Timing-channel measurement harness for the enumeration disclosure in
// auth.Service.RequestPasswordReset's doc, point 5. Run it with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/ -run TimingChannel -v
//
// -v is required: this harness REPORTS, it does not assert on any timing
// threshold, so its whole output is t.Log.
//
// # Why this file exists
//
// RequestPasswordReset's doc, and the readme's "Enumeration safety is
// bounded, not absolute" section, disclose a measured residual timing
// channel — a known address answers materially slower than an unknown one,
// because the known branch performs two Store writes the unknown branch has
// no user row to perform. That is the number the readme uses to argue the
// channel is practical against a single suspected address, which makes it
// the most load-bearing security disclosure in the package. It was carried
// as prose with nothing in the tree that produced it: it could not be
// re-derived, re-checked after a change, or noticed if a later commit
// widened it. This file is what produces it.
//
// # Why it must not assert a threshold
//
// The absolute figures are a property of one machine, one PostgreSQL, and
// one loopback, not of this package. A test that failed when a median moved
// would fail on someone else's laptop, in CI under load, and on a faster
// disk — and a flaky security test gets deleted, taking the measurement
// with it. So the only conditions this harness fails on are ones that mean
// the MEASUREMENT ITSELF is invalid: a "known" address that did not answer
// ok=true, an "unknown" address that did, or a Store error. Everything about
// the timing is logged.
package dropsstore_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/uid"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

// timingSamples is how many SAMPLES per branch the harness reports a
// distribution over. Each sample is a batch of calls (see calibrate), so
// the call count per branch is this times the batch size.
// AUTHLAYER_TIMING_SAMPLES overrides it for a quicker smoke run or a
// longer, tighter one.
func timingSamples(t *testing.T) int {
	t.Helper()
	if raw := os.Getenv("AUTHLAYER_TIMING_SAMPLES"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			t.Fatalf("AUTHLAYER_TIMING_SAMPLES = %q, want a positive integer", raw)
		}
		return n
	}
	return 100
}

// timingBackgroundRows is how many verification rows belonging to OTHER
// users the harness seeds before measuring. It defaults to 0, which is the
// configuration every shipped figure was produced under, so a plain run
// stays comparable to the disclosure in
// auth.Service.RequestPasswordReset's doc.
//
// Set AUTHLAYER_TIMING_BACKGROUND_ROWS to a large number to measure the one
// thing a default run cannot: how the known branch's cost scales with the
// size of the verifications table. The known branch's
// DeleteVerificationsByUserAndPurpose filters on (user_id, purpose); with
// the index NewAuthSchema registers on that pair the cost is a function of
// this user's own rows, and with the index dropped it is a function of the
// whole table. Running the harness at 0 and at, say, 40000 — and again with
// the index dropped — is what turns "a deployment's channel is wider than
// this" into a measured statement instead of an assumption.
func timingBackgroundRows(t *testing.T) int {
	t.Helper()
	raw := os.Getenv("AUTHLAYER_TIMING_BACKGROUND_ROWS")
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		t.Fatalf("AUTHLAYER_TIMING_BACKGROUND_ROWS = %q, want a non-negative integer", raw)
	}
	return n
}

// seedBackgroundVerifications inserts n verification rows spread over n/4
// synthetic users, none of them the address under measurement. They are
// what a real deployment's verifications table holds and the harness's
// otherwise-empty one does not: other people's pending tokens. Inserted in
// one multi-row statement per chunk, since 40000 round trips would dominate
// the test's runtime without teaching anything.
func seedBackgroundVerifications(t *testing.T, sqlDB *sql.DB, table string, n int) {
	t.Helper()
	if n <= 0 {
		return
	}
	ctx := context.Background()
	const chunk = 1000
	purposes := []string{"signup", "email_change", "password_reset", "password_reset"}
	now := time.Now().UTC()
	for done := 0; done < n; done += chunk {
		size := chunk
		if rem := n - done; rem < size {
			size = rem
		}
		var b strings.Builder
		b.WriteString("INSERT INTO " + table + " (id, user_id, token_hash, purpose, email, expires_at, created_at) VALUES ")
		args := make([]any, 0, size*7)
		user := ""
		for i := 0; i < size; i++ {
			if i%4 == 0 {
				user = uid.NewV7()
			}
			if i > 0 {
				b.WriteString(", ")
			}
			o := i * 7
			fmt.Fprintf(&b, "($%d,$%d,$%d,$%d,$%d,$%d,$%d)", o+1, o+2, o+3, o+4, o+5, o+6, o+7)
			args = append(args,
				uid.NewV7(), user, uid.NewV7()+uid.NewV7(), purposes[i%4],
				"bg-"+uid.NewV7()+"@example.com", now.Add(time.Hour), now)
		}
		if _, err := sqlDB.ExecContext(ctx, b.String(), args...); err != nil {
			t.Fatalf("seeding background verifications: %v", err)
		}
	}
	if _, err := sqlDB.ExecContext(ctx, "ANALYZE "+table); err != nil {
		t.Fatalf("ANALYZE %s: %v", table, err)
	}
}

// timingWarmup batches are run and DISCARDED before any sample is kept, per
// branch. The first calls against a fresh connection pay for statement
// preparation, PostgreSQL's own plan cache, and page cache misses on tables
// that were created moments earlier — costs an attacker sampling a live
// system does not pay and that would otherwise land entirely in whichever
// branch happened to run first.
const timingWarmup = 5

// clockGranularity measures the smallest interval this machine's
// time.Now() can actually resolve, by taking consecutive readings and
// keeping the smallest non-zero difference.
//
// This is not a formality. On the Windows machine this harness was last run
// on, time.Now() advances in steps of about 539µs: 199,997 of 200,000
// consecutive pairs read as an IDENTICAL instant. A sub-millisecond
// operation timed with one clock pair there does not come back noisy, it
// comes back QUANTIZED — a first version of this harness reported the
// unknown branch's minimum as 0µs and its 5th percentile as 510µs, which
// are not measurements of anything. Linux and macOS typically resolve tens
// of nanoseconds and have no such problem. The harness adapts rather than
// assuming either (see calibrate), and logs what it found so a reader can
// judge the figures.
func clockGranularity() time.Duration {
	best := time.Duration(0)
	for i := 0; i < 200000; i++ {
		a := time.Now()
		b := time.Now()
		if d := b.Sub(a); d > 0 && (best == 0 || d < best) {
			best = d
		}
	}
	if best == 0 {
		// Every pair read identical — the clock is coarser than this loop
		// could catch. Report something conservative rather than zero, so
		// calibrate does not conclude per-call timing is exact.
		return time.Millisecond
	}
	return best
}

// samples holds one branch's per-call figures, unsorted until summarize is
// called. Each entry is one batch's elapsed time divided by the batch size.
type samples struct {
	name string
	d    []time.Duration
}

func (s *samples) add(d time.Duration) { s.d = append(s.d, d) }

// percentile returns the p-th percentile by NEAREST RANK: the smallest
// sample at or above p% of the (sorted) distribution. No interpolation —
// every value reported is a value that was actually measured, which is the
// right stance for a disclosure someone may later try to reproduce by hand.
// s.d must already be sorted.
func (s *samples) percentile(p float64) time.Duration {
	if len(s.d) == 0 {
		return 0
	}
	rank := int(float64(len(s.d))*p/100 + 0.9999999)
	if rank < 1 {
		rank = 1
	}
	if rank > len(s.d) {
		rank = len(s.d)
	}
	return s.d[rank-1]
}

func (s *samples) mean() time.Duration {
	if len(s.d) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range s.d {
		total += d
	}
	return total / time.Duration(len(s.d))
}

// summarize sorts the samples in place and returns one report line.
func (s *samples) summarize() string {
	sort.Slice(s.d, func(i, j int) bool { return s.d[i] < s.d[j] })
	return fmt.Sprintf(
		"%-10s n=%d  min=%s  p5=%s  p25=%s  MEDIAN=%s  p75=%s  p95=%s  max=%s  mean=%s",
		s.name, len(s.d),
		us(s.d[0]), us(s.percentile(5)), us(s.percentile(25)),
		us(s.percentile(50)), us(s.percentile(75)), us(s.percentile(95)),
		us(s.d[len(s.d)-1]), us(s.mean()),
	)
}

// us renders a duration in whole microseconds, the unit the shipped
// disclosure is written in.
func us(d time.Duration) string {
	return fmt.Sprintf("%dµs", d.Microseconds())
}

// TestRequestPasswordResetTimingChannelLive measures the known-address
// versus unknown-address branch of auth.Service.RequestPasswordReset
// against a live PostgreSQL-backed Store, and reports medians and
// percentiles. It is the harness behind that method's doc, point 5, and
// behind the readme's "Enumeration safety is bounded, not absolute".
//
// # How the two branches are kept comparable
//
// The two branches are INTERLEAVED, one batch each per iteration, with the
// order rotated on alternating iterations. Timing a whole block of one
// branch and then a whole block of the other would attribute any drift over
// the run — another process waking up, PostgreSQL autovacuum, CPU thermal
// behaviour, table bloat accumulating from this harness's own writes — to
// whichever branch happened to run during it. Interleaving makes both
// branches share that drift; rotating the order stops the later batches of
// a group from systematically inheriting the earlier ones' cache state.
//
// Both branches use ONE address each for the whole run, which is what the
// disclosure describes: the channel is about repeatedly sampling a single
// suspected address, not about scanning many.
//
// # What one sample is
//
// A sample is a batch of b consecutive calls on ONE branch, timed with a
// single clock pair and divided by b — a per-call mean, not a single call's
// latency. b is calibrated at runtime from this machine's measured clock
// granularity (see clockGranularity and calibrate) and is 1 on a machine
// whose clock resolves individual calls honestly. Batching is what keeps
// the figures meaningful on a coarse clock; both branches are batched
// identically at the same b, so the comparison between them is unaffected
// either way. It does mean the reported spread is the spread of b-call
// means, which is tighter than the spread of individual calls — the
// MEDIANS and the DELTA between branches, which is what the disclosure
// rests on, are unaffected.
//
// # What one run does and does not settle
//
// The unknown branch is stable across runs; the known branch is not,
// because it is dominated by write latency and that varies with whatever
// else the host and its storage stack are doing. Six runs on one machine
// (Windows host, PostgreSQL in a container, loopback) gave known medians
// between 3254µs and 8699µs against unknown medians between 486µs and
// 1006µs — a delta between 2.8ms and 8.0ms, a ratio between 5.5x and
// 12.3x. What held on EVERY run, and is the durable claim, is the shape:
// the known branch's 5th percentile above the unknown branch's 95th, and
// the control indistinguishable from the unknown branch. Anyone quoting an
// absolute figure from this harness should quote a range over several runs
// and name the machine, not a single median. The same machine reported
// known medians of 9527µs to 16741µs on an earlier occasion with the same
// code, which is the strongest available warning against reading a single
// median as a property of this package: the host moved further between
// sittings than adding an index to the schema moved the measurement (see
// timingBackgroundRows).
//
// # The control
//
// A third branch measures a SECOND unknown address. Two unknown branches
// differ only in the bytes of an address that identifies nobody, so they
// must come out indistinguishable. If the control showed a separation
// anywhere near the known-versus-unknown one, this harness would be
// measuring something other than the branch — sampling order, address
// length, one address's hash landing in a hotter index page — and its main
// number would mean nothing. The control is reported alongside the result
// so a reader can see it held on the run that produced the figure.
func TestRequestPasswordResetTimingChannelLive(t *testing.T) {
	st, sqlDB := newTimingAuthStore(t)
	svc := newLiveAuthService(st)
	ctx := context.Background()
	n := timingSamples(t)
	vacuum := vacuumer(t, sqlDB, st)

	const ip = "203.0.113.9"
	knownEmail := "timing-known-" + uid.NewV7() + "@example.com"
	unknownEmail := "timing-unknown-" + uid.NewV7() + "@example.com"
	controlEmail := "timing-control-" + uid.NewV7() + "@example.com"

	if bg := timingBackgroundRows(t); bg > 0 {
		seedBackgroundVerifications(t, sqlDB, st.Schema().Verifications.Name(), bg)
		t.Logf("BACKGROUND seeded %d verification rows for other users — see timingBackgroundRows", bg)
	}

	res, err := svc.SignUp(ctx, knownEmail, liveTestPassword)
	if err != nil {
		t.Fatalf("SignUp(known address): %v", err)
	}
	if !res.Created {
		t.Fatalf("SignUp(known address).Created = false, want true — the known branch would not be known")
	}

	// call runs one RequestPasswordReset. It fails the test if the branch
	// taken was not the one this address is supposed to take: a mis-signed
	// measurement is worse than none, and unlike a timing figure this
	// condition is machine-independent.
	call := func(email string, wantOK bool) {
		t.Helper()
		_, ok, err := svc.RequestPasswordReset(ctx, email, ip)
		if err != nil {
			t.Fatalf("RequestPasswordReset(%s): %v", email, err)
		}
		if ok != wantOK {
			t.Fatalf("RequestPasswordReset(%s) ok = %v, want %v — this address is not on the branch this harness assumes",
				email, ok, wantOK)
		}
	}

	// batch times b consecutive calls on one branch with a single clock
	// pair and returns the per-call mean.
	batch := func(email string, wantOK bool, b int) time.Duration {
		t.Helper()
		start := time.Now()
		for i := 0; i < b; i++ {
			call(email, wantOK)
		}
		return time.Since(start) / time.Duration(b)
	}

	// Warm up before calibrating, so calibration measures steady-state cost
	// rather than first-call setup.
	for i := 0; i < timingWarmup; i++ {
		batch(knownEmail, true, 8)
		batch(unknownEmail, false, 8)
		batch(controlEmail, false, 8)
	}

	vacuum(ctx)
	granularity := clockGranularity()
	b := calibrate(t, granularity, batch(unknownEmail, false, 64))
	t.Logf("CLOCK    time.Now() granularity = %s → batch size b = %d call(s) per sample, %d samples per branch (%d calls per branch)",
		us(granularity), b, n, b*n)

	known := &samples{name: "KNOWN"}
	unknown := &samples{name: "unknown"}
	control := &samples{name: "control"}

	for i := 0; i < n; i++ {
		// Emulate autovacuum, OUTSIDE the timed batches — see vacuumer's
		// doc for why this is restoring realism rather than hiding a cost.
		if i%vacuumEvery == 0 {
			vacuum(ctx)
		}
		// Rotate the within-group order every iteration — see the method doc.
		switch i % 3 {
		case 0:
			known.add(batch(knownEmail, true, b))
			unknown.add(batch(unknownEmail, false, b))
			control.add(batch(controlEmail, false, b))
		case 1:
			unknown.add(batch(unknownEmail, false, b))
			control.add(batch(controlEmail, false, b))
			known.add(batch(knownEmail, true, b))
		default:
			control.add(batch(controlEmail, false, b))
			known.add(batch(knownEmail, true, b))
			unknown.add(batch(unknownEmail, false, b))
		}
	}

	// Report drift BEFORE summarize sorts the slices in place.
	t.Logf("DRIFT    first third vs last third of the run (median):  KNOWN %s → %s   unknown %s → %s",
		us(medianOf(known.d[:len(known.d)/3])), us(medianOf(known.d[len(known.d)*2/3:])),
		us(medianOf(unknown.d[:len(unknown.d)/3])), us(medianOf(unknown.d[len(unknown.d)*2/3:])))

	t.Log("RequestPasswordReset timing, live PostgreSQL, interleaved branches, per-call means")
	t.Log(known.summarize())
	t.Log(unknown.summarize())
	t.Log(control.summarize())

	kMed, uMed, cMed := known.percentile(50), unknown.percentile(50), control.percentile(50)
	t.Logf("RESULT   known-vs-unknown Δmedian = %s   ratio = %.1f×",
		us(kMed-uMed), float64(kMed)/float64(uMed))
	t.Logf("CONTROL  unknown-vs-unknown Δmedian = %s   ratio = %.2f×  (must be near 0µs / 1.0×)",
		us(cMed-uMed), float64(cMed)/float64(uMed))

	// Disjointness as the disclosure states it: the known branch's 5th
	// percentile above the unknown branch's 95th means fewer than one
	// sample in twenty of each overlaps, so a single sample already
	// separates the branches most of the time on this machine. Logged,
	// never asserted.
	kP5, uP95 := known.percentile(5), unknown.percentile(95)
	t.Logf("SPREAD   known p5 = %s vs unknown p95 = %s — disjoint at those percentiles: %v",
		us(kP5), us(uP95), kP5 > uP95)
	t.Logf("SPREAD   control p5 = %s vs unknown p95 = %s — disjoint at those percentiles: %v (want false)",
		us(control.percentile(5)), us(uP95), control.percentile(5) > uP95)

	// Restate what the harness DOES prove, so a reader of the output alone
	// cannot mistake it for an assertion that the channel is acceptable.
	t.Log("This harness reports; it asserts no threshold. WithPasswordResetRateLimiter is what bounds the channel — see RequestPasswordReset's doc, point 5.")
}

// calibrate picks the batch size from the measured clock granularity and an
// approximate per-call cost of the FASTEST branch (the unknown one — it
// performs no writes, so it sets the floor every other branch clears).
//
// The target is a batch whose elapsed time is at least 20 clock ticks, which
// holds the quantization error on one sample to about granularity/2/b. On
// the Windows machine this was last run on that is 539µs/2/16 ≈ 17µs against
// a delta of several thousand — negligible. On a machine whose clock
// resolves a single call outright (granularity well under the per-call
// cost), b comes out 1 and every sample is one real call, exactly as the
// original disclosure describes.
func calibrate(t *testing.T, granularity, perCall time.Duration) int {
	t.Helper()
	if perCall <= 0 {
		t.Fatalf("calibration measured a non-positive per-call cost (%s) — the clock is unusable for this harness", perCall)
	}
	const ticksPerBatch = 20
	b := int((granularity*ticksPerBatch + perCall - 1) / perCall)
	if b < 1 {
		b = 1
	}
	if b > 512 {
		// A clock this coarse relative to the work would make the run take
		// hours. Cap it and let the log say so rather than hanging.
		t.Logf("CLOCK    granularity %s against a %s call wants b=%d; capped at 512", us(granularity), us(perCall), b)
		b = 512
	}
	return b
}

// vacuumEvery is how many sampling iterations run between VACUUMs of the
// verifications table. Without any vacuuming the known branch's cost climbs
// monotonically through the run — 6283µs median over 400 calls against
// 31772µs over 1500, with a within-run p25→p95 of 25535µs→50734µs — because
// every known-branch call leaves another dead tuple behind for the DELETE
// to walk past (see vacuumer). That is the harness measuring its own churn.
// 5 keeps the table near its steady state without letting VACUUM's own I/O
// land on top of every single timed batch; the DRIFT line reports whether
// it worked.
const vacuumEvery = 5

// vacuumer returns a function that VACUUMs the verifications table, run
// OUTSIDE any timed batch. Plain VACUUM, not VACUUM (ANALYZE): re-computing
// statistics mid-run can change the query plan under the measurement, which
// is precisely the kind of step change a timing harness must not introduce
// itself.
//
// This is restoring realism, not hiding a cost. The known branch's two
// writes are a DELETE and an INSERT on verifications for the same user, so
// hammering one address as fast as a loop can leaves a dead tuple per call
// in a table nothing is reclaiming, and every later DELETE walks past them.
// The measurements in this paragraph predate the (user_id, purpose) index
// NewAuthSchema now registers, when the DELETE was a sequential scan of the
// whole table and this effect was at its worst: an unvacuumed version of
// this harness measured a KNOWN median of 31772µs over 1500 calls against
// 6283µs over 400, with a within-run p25→p95 spread of 25535µs→50734µs.
// That is the harness measuring its own churn, not the branch. The index
// scopes the effect to this user's own dead entries rather than every
// user's; it does not remove it, so the vacuuming stays.
//
// A live server runs autovacuum; it simply does not trigger at this
// harness's rate against a table this small. Vacuuming every iteration puts
// the table back in its cleanest possible state, and the DRIFT line in the
// report is what shows whether it worked — if the first third and last
// third of the run disagree materially, the run was not stationary and the
// median is not a property of the branch.
//
// That makes the reported delta a FLOOR rather than a typical value: this
// harness runs against a table holding a single live row and nothing
// unreclaimed, which is the cheapest the known branch's DELETE can
// possibly be. What the index changed is which term of that gap grows.
// Measured on this machine at a background of 40000 other users' pending
// tokens (AUTHLAYER_TIMING_BACKGROUND_ROWS), the known branch's floor —
// its minimum sample, the statistic least contaminated by host noise —
// went 2347–2481µs to 4708–5005µs WITHOUT the index and 2389–2816µs to
// 2386–2574µs WITH it. So table size no longer widens the channel;
// unreclaimed dead tuples for the address under attack still do.
func vacuumer(t *testing.T, sqlDB *sql.DB, st *dropsstore.AuthStore) func(context.Context) {
	t.Helper()
	table := st.Schema().Verifications.Name()
	return func(ctx context.Context) {
		if _, err := sqlDB.ExecContext(ctx, "VACUUM "+table); err != nil {
			t.Fatalf("VACUUM %s: %v", table, err)
		}
	}
}

// medianOf returns the median of an UNSORTED slice without disturbing it,
// so the caller can report within-run drift before the summary sorts
// everything in place.
func medianOf(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	c := make([]time.Duration, len(d))
	copy(c, d)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

// newTimingAuthStore is newLiveAuthStoreWarmed with the raw *sql.DB handed
// back too, which this harness needs for VACUUM — a statement drops has no
// builder for, and one that cannot run inside a transaction.
func newTimingAuthStore(t *testing.T) (*dropsstore.AuthStore, *sql.DB) {
	t.Helper()
	sqlDB, db := openLiveDB(t)
	sqlDB.SetMaxOpenConns(4)
	sqlDB.SetMaxIdleConns(4)

	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()
	dropAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, db, st) })

	var one int
	if err := sqlDB.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("pool warm-up query: %v", err)
	}
	return st, sqlDB
}
