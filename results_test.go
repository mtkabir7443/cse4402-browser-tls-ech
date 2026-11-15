package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type resultHarness struct {
	store *resultsStore
	mux   *http.ServeMux
	now   time.Time
}

func newResultHarness(t *testing.T) *resultHarness {
	t.Helper()
	h := &resultHarness{now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	h.store = newResultsStore(t.TempDir(), "")
	h.store.now = func() time.Time { return h.now }
	h.mux = http.NewServeMux()
	h.store.register(h.mux)
	return h
}

func (h *resultHarness) request(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != nil {
		var err error
		b, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.RemoteAddr = "192.0.2.42:32100"
	r.Header.Set("User-Agent", "Mozilla/5.0 test browser")
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	return w
}

func resultRegistration(id, caseID string) runRegistration {
	return runRegistration{RunID: id, BrowserID: "firefox-current", BrowserProduct: "Firefox", BrowserVersion: "160.0", Distribution: "official", OS: "Windows 11", Settings: map[string]any{"fresh_profile": true}, CaseID: caseID, Repetition: 1, BatchID: "pilot"}
}

func (h *resultHarness) register(t *testing.T, id, caseID string) {
	t.Helper()
	w := h.request(t, "POST", "/api/runs", resultRegistration(id, caseID))
	if w.Code != 201 {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
}

func (h *resultHarness) event(t *testing.T, filename string, e map[string]any) {
	t.Helper()
	if _, ok := e["timestamp"]; !ok {
		e["timestamp"] = h.now.Add(time.Second).Format(time.RFC3339Nano)
	}
	if _, ok := e["client_ip"]; !ok {
		e["client_ip"] = "192.0.2.42"
	}
	if e["event"] == "http_result" {
		if _, ok := e["user_agent"]; !ok {
			e["user_agent"] = "Mozilla/5.0 Firefox/160.0"
		}
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(h.store.dir, filename), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(append(b, '\n'))
	closeErr := f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func (h *resultHarness) complete(t *testing.T, id string, input runCompletion) runRecord {
	t.Helper()
	h.now = h.now.Add(10 * time.Second)
	w := h.request(t, "POST", "/api/runs/"+id+"/complete", input)
	if w.Code != 200 {
		t.Fatalf("complete: %d %s", w.Code, w.Body)
	}
	var result runRecord
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestResultsRequireServerEvidenceAndOwnClientIP(t *testing.T) {
	h := newResultHarness(t)
	h.register(t, "unproven", "E1")
	result := h.complete(t, "unproven", runCompletion{BrowserOutcome: "connected", Observations: map[string]any{"tls_version": "TLS 1.3", "ech_accepted": true, "client_ip": "6.6.6.6"}})
	if result.Outcome != "inconclusive" || result.ECHAccepted != nil || result.TLSVersion != "" {
		t.Fatalf("client fabricated negotiation became authoritative: %+v", result)
	}
	if result.ClientIP != "192.0.2.42" {
		t.Fatalf("client IP not socket-owned: %s", result.ClientIP)
	}
	if result.ClientObservations["ech_accepted"] != true {
		t.Fatal("client report not retained as separate diagnostic evidence")
	}
}

func TestResultsServerEvidenceOverridesBrowserClaimsAndSurvivesRestart(t *testing.T) {
	h := newResultHarness(t)
	h.register(t, "actual", "E2")
	h.event(t, "server-events.jsonl", map[string]any{"event": "http_result", "run_id": "actual", "host": "baseline.tlslab.test:9443", "tls_version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "ech_accepted": false, "resumed": false, "user_agent": "Firefox/160.0", "remote_address": "192.0.2.42:45600"})
	result := h.complete(t, "actual", runCompletion{BrowserOutcome: "connected", Observations: map[string]any{"ech_accepted": true}})
	if result.Outcome != "connected_no_ech" || result.ECHAccepted == nil || *result.ECHAccepted || result.ExpectedMatch == nil || !*result.ExpectedMatch {
		t.Fatalf("incorrect baseline: %+v", result)
	}
	reopened := newResultsStore(h.store.dir, "")
	runs, err := reopened.loadRuns()
	if err != nil {
		t.Fatal(err)
	}
	if runs["actual"].Outcome != "connected_no_ech" || len(runs["actual"].Evidence) != 1 {
		t.Fatal("durable normalized result not reconstructed")
	}
	if runs["actual"].MeasuredUserAgent != "Firefox/160.0" {
		t.Fatal("server observed user agent missing")
	}
}

func TestResultsStaleECHRecoveryRequiresOrderedOuterEvidence(t *testing.T) {
	for _, outer := range []bool{true, false} {
		t.Run(fmt.Sprint(outer), func(t *testing.T) {
			h := newResultHarness(t)
			h.register(t, "stale", "E3")
			if outer {
				h.event(t, "server-events.jsonl", map[string]any{"event": "handshake", "fixture": "tls13-ech", "success": true, "server_name": "public.tlslab.test", "ech_accepted": false, "tls_version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256"})
			}
			h.event(t, "server-events.jsonl", map[string]any{"event": "http_result", "timestamp": h.now.Add(2 * time.Second).Format(time.RFC3339Nano), "run_id": "stale", "host": "stale.tlslab.test:9443", "tls_version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "ech_accepted": true, "resumed": false})
			result := h.complete(t, "stale", runCompletion{BrowserOutcome: "connected"})
			expected := "ech_accepted_retry_unverified"
			if outer {
				expected = "ech_recovered"
			}
			if result.Outcome != expected {
				t.Fatalf("got %s want %s", result.Outcome, expected)
			}
			if outer && !strings.Contains(result.RetryEvidence, "not directly decoded") {
				t.Fatal("recovery overclaims direct retry decoding")
			}
		})
	}
}

func TestResultsFailuresSeparateRejectionFromInfrastructureAndAmbiguity(t *testing.T) {
	tests := []struct {
		name, message, want string
		interference        bool
	}{
		{"version", "tls: client offered only unsupported versions: [304 303]", "rejected_protocol", false},
		{"cipher", "tls: no cipher suite supported by both client and server", "rejected_cipher_or_signature", false},
		{"certificate", "remote error: tls: bad certificate", "infrastructure_error", false},
		{"timeout", "context deadline exceeded", "inconclusive", false},
		{"ambiguous", "tls: client offered only unsupported versions: [304 303]", "inconclusive", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newResultHarness(t)
			h.register(t, "failure", "V1")
			h.event(t, "server-events.jsonl", map[string]any{"event": "handshake", "fixture": "tls10", "success": false, "error": test.message})
			if test.interference {
				h.event(t, "server-events.jsonl", map[string]any{"event": "http_result", "run_id": "unregistered-other", "host": "tls10.tlslab.test:9440", "tls_version": "TLS 1.0"})
			}
			result := h.complete(t, "failure", runCompletion{BrowserOutcome: "failed", BrowserError: "TypeError: Failed to fetch"})
			if result.Outcome != test.want {
				t.Fatalf("got %s want %s (%s)", result.Outcome, test.want, result.Reason)
			}
		})
	}
}

func TestResultsWrongIPHostOrTimeCannotProveMeasurement(t *testing.T) {
	tests := []struct {
		name   string
		change func(map[string]any, *resultHarness)
	}{
		{"wrong-ip", func(e map[string]any, h *resultHarness) { e["client_ip"] = "192.0.2.99" }},
		{"wrong-host", func(e map[string]any, h *resultHarness) { e["host"] = "baseline.tlslab.test:9443" }},
		{"wrong-port", func(e map[string]any, h *resultHarness) { e["host"] = "valid.tlslab.test:9442" }},
		{"past", func(e map[string]any, h *resultHarness) {
			e["timestamp"] = h.now.Add(-time.Second).Format(time.RFC3339Nano)
		}},
		{"future", func(e map[string]any, h *resultHarness) {
			e["timestamp"] = h.now.Add(time.Hour).Format(time.RFC3339Nano)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newResultHarness(t)
			h.register(t, "bound", "E1")
			e := map[string]any{"event": "http_result", "run_id": "bound", "host": "valid.tlslab.test:9443", "tls_version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "ech_accepted": true}
			test.change(e, h)
			h.event(t, "server-events.jsonl", e)
			result := h.complete(t, "bound", runCompletion{BrowserOutcome: "connected"})
			if result.Outcome != "inconclusive" {
				t.Fatalf("unrelated evidence accepted: %+v", result)
			}
		})
	}
}

func TestResultsRestrictedSuiteMismatchAndResumptionNotAccepted(t *testing.T) {
	for _, resumed := range []bool{false, true} {
		t.Run(fmt.Sprint(resumed), func(t *testing.T) {
			h := newResultHarness(t)
			h.register(t, "suite", "C3")
			suite := "TLS_AES_256_GCM_SHA384"
			if resumed {
				suite = "TLS_AES_128_GCM_SHA256"
			}
			h.event(t, "suite-events.jsonl", map[string]any{"event": "http_result", "fixture": "tls13-aes128", "run_id": "suite", "host": "tls13-aes128.tlslab.test:9451", "tls_version": "TLS 1.3", "cipher_suite": suite, "ech_accepted": false, "resumed": resumed})
			result := h.complete(t, "suite", runCompletion{BrowserOutcome: "connected"})
			expected := "fixture_mismatch"
			if resumed {
				expected = "inconclusive"
			}
			if result.Outcome != expected {
				t.Fatalf("got %s want %s", result.Outcome, expected)
			}
		})
	}
}

func TestResultsRegistrationAndCompletionAreImmutableIdempotent(t *testing.T) {
	h := newResultHarness(t)
	reg := resultRegistration("immutable", "V3")
	first := h.request(t, "POST", "/api/runs", reg)
	if first.Code != 201 {
		t.Fatal(first.Body)
	}
	if second := h.request(t, "POST", "/api/runs", reg); second.Code != 200 {
		t.Fatalf("idempotent registration: %s", second.Body)
	}
	reg.CaseID = "V4"
	if changed := h.request(t, "POST", "/api/runs", reg); changed.Code != 409 {
		t.Fatal("changed registration accepted")
	}
	if concurrent := h.request(t, "POST", "/api/runs", resultRegistration("other", "V4")); concurrent.Code != 409 {
		t.Fatal("overlapping same-client registration accepted")
	}
	input := runCompletion{BrowserOutcome: "aborted", BrowserError: "Browser exited before probe"}
	_ = h.complete(t, "immutable", input)
	if same := h.request(t, "POST", "/api/runs/immutable/complete", input); same.Code != 200 {
		t.Fatal("idempotent completion failed")
	}
	if changed := h.request(t, "POST", "/api/runs/immutable/complete", runCompletion{BrowserOutcome: "connected"}); changed.Code != 409 {
		t.Fatal("changed completion accepted")
	}
	journal, err := os.ReadFile(filepath.Join(h.store.dir, "runs.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(journal, []byte{'\n'}) != 2 {
		t.Fatalf("idempotent retries wrote extra journal records: %s", journal)
	}
	if next := h.request(t, "POST", "/api/runs", resultRegistration("other", "V4")); next.Code != 201 {
		t.Fatalf("next serial run refused: %s", next.Body)
	}
}

func TestResultsSummaryIncludesMissingCellsAndBatchSeparation(t *testing.T) {
	h := newResultHarness(t)
	h.register(t, "pilot-run", "V1")
	_ = h.complete(t, "pilot-run", runCompletion{BrowserOutcome: "failed"})
	reg := resultRegistration("final-run", "E1")
	reg.BatchID = "final"
	if w := h.request(t, "POST", "/api/runs", reg); w.Code != 201 {
		t.Fatal(w.Body)
	}
	w := h.request(t, "GET", "/api/summary?batch_id=final", nil)
	var summary resultSummary
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Registered != 1 || summary.Completed != 0 || len(summary.Browsers) != 1 || len(summary.Cells) != 12 {
		t.Fatalf("incorrect summary: %+v", summary)
	}
	for _, cell := range summary.Cells {
		if cell.CaseID == "E1" && cell.Pending != 1 {
			t.Fatal("pending E1 missing")
		}
		if cell.CaseID == "V1" && cell.Registered != 0 {
			t.Fatal("pilot leaked into final summary")
		}
	}
	results := h.request(t, "GET", "/api/results?batch_id=final", nil)
	if strings.TrimSpace(results.Body.String()) != "[]" {
		t.Fatal("uncompleted run appeared as completed measurement")
	}
}

func TestResultsExportRetainsRawObservedIPAndQuotesCSV(t *testing.T) {
	h := newResultHarness(t)
	reg := resultRegistration("export", "V1")
	reg.BrowserProduct = "Firefox, test"
	if w := h.request(t, "POST", "/api/runs", reg); w.Code != 201 {
		t.Fatal(w.Body)
	}
	_ = h.complete(t, "export", runCompletion{BrowserOutcome: "failed", BrowserError: "=HYPERLINK(\"bad\")"})
	w := h.request(t, "GET", "/api/export?format=csv", nil)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][3] != "Firefox, test" || rows[1][9] != "192.0.2.42" || !strings.HasPrefix(rows[1][20], "'=") {
		t.Fatalf("bad CSV: %#v", rows)
	}
	j := h.request(t, "GET", "/api/export?format=jsonl", nil)
	var row runRecord
	if err := json.Unmarshal(bytes.TrimSpace(j.Body.Bytes()), &row); err != nil {
		t.Fatal(err)
	}
	if row.ClientIP != "192.0.2.42" || row.RunID != "export" {
		t.Fatalf("bad JSONL: %+v", row)
	}
}

func TestResultsEvidenceAndJournalFailuresDoNotAcknowledgeCompletion(t *testing.T) {
	t.Run("partial-event", func(t *testing.T) {
		h := newResultHarness(t)
		h.register(t, "partial", "V3")
		if err := os.WriteFile(filepath.Join(h.store.dir, "server-events.jsonl"), []byte(`{"event":"handshake"`), 0600); err != nil {
			t.Fatal(err)
		}
		w := h.request(t, "POST", "/api/runs/partial/complete", runCompletion{BrowserOutcome: "failed"})
		if w.Code != 500 {
			t.Fatalf("partial evidence acknowledged: %d %s", w.Code, w.Body)
		}
		runs, err := h.store.loadRuns()
		if err != nil {
			t.Fatal(err)
		}
		if runs["partial"].Status != "registered" {
			t.Fatal("failed evidence read completed run")
		}
	})
	t.Run("unwritable-journal", func(t *testing.T) {
		h := newResultHarness(t)
		if err := os.Mkdir(filepath.Join(h.store.dir, "runs.jsonl"), 0700); err != nil {
			t.Fatal(err)
		}
		w := h.request(t, "POST", "/api/runs", resultRegistration("blocked", "V1"))
		if w.Code != 500 {
			t.Fatalf("log failure not propagated: %d", w.Code)
		}
	})
	t.Run("corrupt-journal", func(t *testing.T) {
		h := newResultHarness(t)
		if err := os.WriteFile(filepath.Join(h.store.dir, "runs.jsonl"), []byte("not json\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if w := h.request(t, "GET", "/api/results", nil); w.Code != 500 {
			t.Fatal("corrupt journal silently ignored")
		}
	})
}

func TestResultsRejectMalformedInputAndUnknownCase(t *testing.T) {
	h := newResultHarness(t)
	for _, value := range []any{nil, map[string]any{"run_id": "../../escape"}, func() runRegistration { r := resultRegistration("unknown", "V9"); return r }()} {
		if w := h.request(t, "POST", "/api/runs", value); w.Code != 400 {
			t.Fatalf("invalid body accepted: %d %s", w.Code, w.Body)
		}
	}
	reg := resultRegistration("forged", "V1")
	b, _ := json.Marshal(reg)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	body["client_ip"] = "203.0.113.1"
	if w := h.request(t, "POST", "/api/runs", body); w.Code != 400 {
		t.Fatal("server-owned IP field accepted")
	}
	if w := h.request(t, "DELETE", "/api/cases", nil); w.Code != 405 {
		t.Fatal("wrong method accepted")
	}
	w := h.request(t, "GET", "/api/cases", nil)
	var cases []measurementCase
	if err := json.Unmarshal(w.Body.Bytes(), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 12 {
		t.Fatalf("manifest has %d cases", len(cases))
	}
}

func TestResultsDoNotPromoteCLIOrUnidentifiedHTTPToBrowserMeasurement(t *testing.T) {
	for _, agent := range []string{"Go-http-client/1.1", "curl/8.12", ""} {
		t.Run(agent, func(t *testing.T) {
			h := newResultHarness(t)
			h.register(t, "cli", "V3")
			h.event(t, "server-events.jsonl", map[string]any{"event": "http_result", "run_id": "cli", "host": "tls12.tlslab.test:9442", "tls_version": "TLS 1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "user_agent": agent})
			result := h.complete(t, "cli", runCompletion{BrowserOutcome: "connected"})
			if result.Outcome != "inconclusive" || result.TLSVersion != "" {
				t.Fatalf("CLI observation promoted to browser success: %+v", result)
			}
		})
	}
}

func TestResultsRejectCrossOriginMutations(t *testing.T) {
	h := newResultHarness(t)
	b, _ := json.Marshal(resultRegistration("crossorigin", "V1"))
	r := httptest.NewRequest("POST", "https://127.0.0.1:8443/api/runs", bytes.NewReader(b))
	r.Header.Set("Origin", "https://unrelated.example")
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin write accepted: %d", w.Code)
	}
}
