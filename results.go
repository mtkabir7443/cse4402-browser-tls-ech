package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type measurementCase struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Family         string `json:"family"`
	Fixture        string `json:"fixture"`
	ExpectedTLS    string `json:"expected_tls"`
	ExpectedCipher string `json:"expected_cipher,omitempty"`
	ExpectedECH    *bool  `json:"expected_ech,omitempty"`
}

func boolPointer(v bool) *bool { return &v }

func measurementCases() []measurementCase {
	return []measurementCase{
		{"V1", "TLS 1.0 only", "tls10.tlslab.test", 9440, "version", "tls10", "TLS 1.0", "", nil},
		{"V2", "TLS 1.1 only", "tls11.tlslab.test", 9441, "version", "tls11", "TLS 1.1", "", nil},
		{"V3", "TLS 1.2 only", "tls12.tlslab.test", 9442, "version", "tls12", "TLS 1.2", "", nil},
		{"V4", "TLS 1.3 only", "tls13.tlslab.test", 9443, "version", "tls13-ech", "TLS 1.3", "", nil},
		{"C1", "TLS 1.2 / AES-128-GCM", "tls12-aes128.tlslab.test", 9445, "cipher", "tls12-aes128", "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", nil},
		{"C2", "TLS 1.2 / ChaCha20-Poly1305", "tls12-chacha.tlslab.test", 9446, "cipher", "tls12-chacha", "TLS 1.2", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", nil},
		{"C3", "TLS 1.3 / AES-128-GCM", "tls13-aes128.tlslab.test", 9451, "cipher", "tls13-aes128", "TLS 1.3", "TLS_AES_128_GCM_SHA256", nil},
		{"C4", "TLS 1.3 / AES-256-GCM", "tls13-aes256.tlslab.test", 9452, "cipher", "tls13-aes256", "TLS 1.3", "TLS_AES_256_GCM_SHA384", nil},
		{"C5", "TLS 1.3 / ChaCha20-Poly1305", "tls13-chacha.tlslab.test", 9453, "cipher", "tls13-chacha", "TLS 1.3", "TLS_CHACHA20_POLY1305_SHA256", nil},
		{"E1", "Valid ECH configuration", "valid.tlslab.test", 9443, "ech", "tls13-ech", "TLS 1.3", "", boolPointer(true)},
		{"E2", "No advertised ECH configuration", "baseline.tlslab.test", 9443, "ech", "tls13-ech", "TLS 1.3", "", boolPointer(false)},
		{"E3", "Stale ECH configuration / recovery", "stale.tlslab.test", 9443, "ech", "tls13-ech", "TLS 1.3", "", boolPointer(true)},
	}
}

func measurementCaseByID(id string) (measurementCase, bool) {
	for _, c := range measurementCases() {
		if c.ID == id {
			return c, true
		}
	}
	return measurementCase{}, false
}

type runRegistration struct {
	RunID          string         `json:"run_id"`
	BrowserID      string         `json:"browser_id"`
	BrowserProduct string         `json:"browser_product"`
	BrowserVersion string         `json:"browser_version"`
	Distribution   string         `json:"distribution"`
	OS             string         `json:"os"`
	Settings       map[string]any `json:"settings"`
	CaseID         string         `json:"case_id"`
	Repetition     int            `json:"repetition"`
	BatchID        string         `json:"batch_id,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
}

type runCompletion struct {
	BrowserOutcome string         `json:"browser_outcome"`
	BrowserError   string         `json:"browser_error,omitempty"`
	Observations   map[string]any `json:"observations,omitempty"`
}

type resultEvidence struct {
	File          string `json:"file"`
	Line          int    `json:"line"`
	Event         string `json:"event"`
	Timestamp     string `json:"timestamp"`
	RunID         string `json:"run_id,omitempty"`
	Fixture       string `json:"fixture,omitempty"`
	Host          string `json:"host,omitempty"`
	ClientIP      string `json:"client_ip,omitempty"`
	RemoteAddress string `json:"remote_address,omitempty"`
	ServerName    string `json:"server_name,omitempty"`
	TLSVersion    string `json:"tls_version,omitempty"`
	CipherSuite   string `json:"cipher_suite,omitempty"`
	ECHAccepted   *bool  `json:"ech_accepted,omitempty"`
	Resumed       *bool  `json:"resumed,omitempty"`
	Success       *bool  `json:"success,omitempty"`
	Error         string `json:"error,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
}

type runRecord struct {
	runRegistration
	ClientIP           string           `json:"client_ip"`
	RequestUserAgent   string           `json:"request_user_agent"`
	StartedUTC         string           `json:"started_utc"`
	CompletedUTC       string           `json:"completed_utc,omitempty"`
	Status             string           `json:"status"`
	CertificateSHA256  string           `json:"certificate_sha256,omitempty"`
	Outcome            string           `json:"outcome,omitempty"`
	Reason             string           `json:"reason,omitempty"`
	TLSVersion         string           `json:"tls_version,omitempty"`
	CipherSuite        string           `json:"cipher_suite,omitempty"`
	ECHAccepted        *bool            `json:"ech_accepted,omitempty"`
	Resumed            *bool            `json:"resumed,omitempty"`
	ExpectedMatch      *bool            `json:"expected_match,omitempty"`
	RetryEvidence      string           `json:"retry_evidence,omitempty"`
	Correlation        string           `json:"correlation,omitempty"`
	MeasuredUserAgent  string           `json:"measured_user_agent,omitempty"`
	BrowserOutcome     string           `json:"browser_outcome,omitempty"`
	BrowserError       string           `json:"browser_error,omitempty"`
	ClientObservations map[string]any   `json:"client_observations,omitempty"`
	Evidence           []resultEvidence `json:"evidence,omitempty"`
}

type runJournalEntry struct {
	Event string    `json:"event"`
	Run   runRecord `json:"run"`
}

type resultsStore struct {
	mu              sync.Mutex
	dir             string
	certificatePath string
	now             func() time.Time
}

func newResultsStore(dir, certificatePath string) *resultsStore {
	return &resultsStore{dir: dir, certificatePath: certificatePath, now: time.Now}
}

func registerResultsAPI(mux *http.ServeMux) {
	newResultsStore("evidence", filepath.Join(dataDir, "server.pem")).register(mux)
}

func (s *resultsStore) register(mux *http.ServeMux) {
	mux.HandleFunc("/api/cases", s.cases)
	mux.HandleFunc("/api/runs", s.runs)
	mux.HandleFunc("/api/runs/", s.run)
	mux.HandleFunc("/api/results", s.results)
	mux.HandleFunc("/api/summary", s.summary)
	mux.HandleFunc("/api/export", s.export)
}

func writeResultJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func resultError(w http.ResponseWriter, status int, message string) {
	writeResultJSON(w, status, map[string]string{"error": message})
}

func resultMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	if r.Method == http.MethodPost {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "https://"+r.Host {
			resultError(w, http.StatusForbidden, "cross-origin result mutation is not allowed")
			return false
		}
	}
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	resultError(w, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

func decodeResultRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		resultError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		resultError(w, http.StatusBadRequest, "exactly one JSON object is required")
		return false
	}
	return true
}

var resultIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$`)

func validateRegistration(reg runRegistration) error {
	if !resultIDPattern.MatchString(reg.RunID) || !resultIDPattern.MatchString(reg.BrowserID) {
		return errors.New("run_id and browser_id must be 1-120 safe identifier characters")
	}
	if reg.BatchID != "" && !resultIDPattern.MatchString(reg.BatchID) {
		return errors.New("invalid batch_id")
	}
	if _, ok := measurementCaseByID(reg.CaseID); !ok {
		return errors.New("unknown case_id")
	}
	if reg.Repetition < 1 || reg.Repetition > 100 {
		return errors.New("repetition must be between 1 and 100")
	}
	for name, value := range map[string]string{"browser_product": reg.BrowserProduct, "browser_version": reg.BrowserVersion, "distribution": reg.Distribution, "os": reg.OS} {
		if strings.TrimSpace(value) == "" || len(value) > 256 {
			return fmt.Errorf("%s is required and must not exceed 256 bytes", name)
		}
	}
	if reg.Settings == nil {
		return errors.New("settings object is required")
	}
	settings, err := json.Marshal(reg.Settings)
	if err != nil || len(settings) > 16384 {
		return errors.New("settings exceed the 16 KiB limit")
	}
	if len(reg.UserAgent) > 2048 {
		return errors.New("user_agent exceeds the 2048-byte limit")
	}
	return nil
}

func validateCompletion(c runCompletion) error {
	switch c.BrowserOutcome {
	case "connected", "failed", "timeout", "error", "inconclusive", "aborted", "rejected":
	default:
		return errors.New("unknown browser_outcome")
	}
	if len(c.BrowserError) > 8192 {
		return errors.New("browser_error exceeds the 8192-byte limit")
	}
	b, err := json.Marshal(c.Observations)
	if err != nil || len(b) > 16384 {
		return errors.New("observations exceed the 16 KiB limit")
	}
	return nil
}

// Only this service writes runs.jsonl. Each record is appended under s.mu and
// synced before acknowledgement. A malformed journal fails closed on reopening.
func (s *resultsStore) appendRun(event string, run runRecord) error {
	b, err := json.Marshal(runJournalEntry{event, run})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, "runs.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(append(b, '\n'))
	if err == nil && n != len(b)+1 {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func readJSONLines(path string, visit func([]byte, int) error) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	reader := bufio.NewReaderSize(f, 65536)
	for line := 1; ; line++ {
		b, readErr := reader.ReadBytes('\n')
		if len(b) > 1024*1024 {
			return fmt.Errorf("%s:%d: record exceeds limit", filepath.Base(path), line)
		}
		if len(b) > 0 {
			if b[len(b)-1] != '\n' {
				return fmt.Errorf("%s:%d: incomplete journal line", filepath.Base(path), line)
			}
			if len(bytes.TrimSpace(b)) > 0 {
				if err := visit(b, line); err != nil {
					return fmt.Errorf("%s:%d: %w", filepath.Base(path), line, err)
				}
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (s *resultsStore) loadRuns() (map[string]runRecord, error) {
	runs := map[string]runRecord{}
	err := readJSONLines(filepath.Join(s.dir, "runs.jsonl"), func(b []byte, line int) error {
		var e runJournalEntry
		if err := json.Unmarshal(b, &e); err != nil {
			return err
		}
		if err := validateRegistration(e.Run.runRegistration); err != nil {
			return err
		}
		prior, exists := runs[e.Run.RunID]
		switch e.Event {
		case "registered":
			if exists || e.Run.Status != "registered" {
				return errors.New("duplicate or invalid registration")
			}
		case "completed":
			if !exists || prior.Status != "registered" || e.Run.Status != "completed" || !reflect.DeepEqual(prior.runRegistration, e.Run.runRegistration) || prior.ClientIP != e.Run.ClientIP || prior.StartedUTC != e.Run.StartedUTC {
				return errors.New("invalid completion transition")
			}
		default:
			return errors.New("unknown run journal event")
		}
		runs[e.Run.RunID] = e.Run
		return nil
	})
	return runs, err
}

func resultRunList(runs map[string]runRecord, batch string, completedOnly bool) []runRecord {
	rows := []runRecord{}
	for _, run := range runs {
		if (batch == "" || run.BatchID == batch) && (!completedOnly || run.Status == "completed") {
			rows = append(rows, run)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].StartedUTC == rows[j].StartedUTC {
			return rows[i].RunID < rows[j].RunID
		}
		return rows[i].StartedUTC < rows[j].StartedUTC
	})
	return rows
}

func (s *resultsStore) cases(w http.ResponseWriter, r *http.Request) {
	if !resultMethod(w, r, http.MethodGet) {
		return
	}
	writeResultJSON(w, 200, measurementCases())
}

func (s *resultsStore) runs(w http.ResponseWriter, r *http.Request) {
	if !resultMethod(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	var reg runRegistration
	if r.Method == http.MethodPost {
		if !decodeResultRequest(w, r, &reg) {
			return
		}
		if err := validateRegistration(reg); err != nil {
			resultError(w, 400, err.Error())
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, err := s.loadRuns()
	if err != nil {
		resultError(w, 500, "run journal unavailable: "+err.Error())
		return
	}
	if r.Method == http.MethodGet {
		writeResultJSON(w, 200, resultRunList(runs, r.URL.Query().Get("batch_id"), false))
		return
	}
	clientIP := ipOnly(r.RemoteAddr)
	if old, exists := runs[reg.RunID]; exists {
		if old.ClientIP == clientIP && reflect.DeepEqual(old.runRegistration, reg) {
			writeResultJSON(w, 200, old)
		} else {
			resultError(w, 409, "run_id already belongs to a different immutable registration")
		}
		return
	}
	for _, old := range runs {
		if old.BrowserID == reg.BrowserID && (old.BrowserProduct != reg.BrowserProduct || old.BrowserVersion != reg.BrowserVersion || old.Distribution != reg.Distribution || old.OS != reg.OS) {
			resultError(w, 409, "browser_id already identifies different build metadata; choose a distinct browser_id")
			return
		}
		if old.ClientIP == clientIP && old.Status == "registered" {
			resultError(w, 409, "complete the client's outstanding run before registering another: "+old.RunID)
			return
		}
	}
	run := runRecord{runRegistration: reg, ClientIP: clientIP, RequestUserAgent: r.UserAgent(), StartedUTC: s.now().UTC().Format(time.RFC3339Nano), Status: "registered"}
	if s.certificatePath != "" {
		b, err := os.ReadFile(s.certificatePath)
		if err != nil {
			resultError(w, 500, "server certificate fingerprint unavailable")
			return
		}
		digest := sha256.Sum256(b)
		run.CertificateSHA256 = hex.EncodeToString(digest[:])
	}
	if err := s.appendRun("registered", run); err != nil {
		resultError(w, 500, "registration log write failed: "+err.Error())
		return
	}
	writeResultJSON(w, 201, run)
}

func (s *resultsStore) run(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/runs/")
	complete := strings.HasSuffix(path, "/complete")
	id := strings.TrimSuffix(path, "/complete")
	if !resultIDPattern.MatchString(id) {
		resultError(w, 404, "unknown run path")
		return
	}
	if complete {
		if !resultMethod(w, r, http.MethodPost) {
			return
		}
	} else {
		if !resultMethod(w, r, http.MethodGet) {
			return
		}
	}
	var request runCompletion
	if complete {
		if !decodeResultRequest(w, r, &request) {
			return
		}
		if err := validateCompletion(request); err != nil {
			resultError(w, 400, err.Error())
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, err := s.loadRuns()
	if err != nil {
		resultError(w, 500, "run journal unavailable: "+err.Error())
		return
	}
	run, exists := runs[id]
	if !exists {
		resultError(w, 404, "run not found")
		return
	}
	if !complete {
		writeResultJSON(w, 200, run)
		return
	}
	if run.ClientIP != ipOnly(r.RemoteAddr) {
		resultError(w, 403, "completion must use the registration's client IP")
		return
	}
	if run.Status == "completed" {
		old := runCompletion{run.BrowserOutcome, run.BrowserError, run.ClientObservations}
		if reflect.DeepEqual(old, request) {
			writeResultJSON(w, 200, run)
		} else {
			resultError(w, 409, "completed run is immutable")
		}
		return
	}
	run.CompletedUTC = s.now().UTC().Format(time.RFC3339Nano)
	run.BrowserOutcome = request.BrowserOutcome
	run.BrowserError = request.BrowserError
	run.ClientObservations = request.Observations
	events, err := s.loadEvidence()
	if err != nil {
		resultError(w, 500, "measurement evidence unavailable: "+err.Error())
		return
	}
	classifyRun(&run, events, runs)
	run.Status = "completed"
	if err := s.appendRun("completed", run); err != nil {
		resultError(w, 500, "completion log write failed: "+err.Error())
		return
	}
	writeResultJSON(w, 200, run)
}

func (s *resultsStore) loadEvidence() ([]resultEvidence, error) {
	var events []resultEvidence
	// Main Go events use this same lock. Independent suite writes are complete
	// JSONL records; a partial line returns a retriable error, never a verdict.
	eventMu.Lock()
	defer eventMu.Unlock()
	for _, filename := range []string{"server-events.jsonl", "suite-events.jsonl"} {
		err := readJSONLines(filepath.Join(s.dir, filename), func(b []byte, line int) error {
			var e resultEvidence
			if err := json.Unmarshal(b, &e); err != nil {
				return err
			}
			if e.Event != "handshake" && e.Event != "http_result" {
				return nil
			}
			if _, err := time.Parse(time.RFC3339Nano, e.Timestamp); err != nil {
				return fmt.Errorf("event timestamp: %w", err)
			}
			e.File = filename
			e.Line = line
			events = append(events, e)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, events[i].Timestamp)
		b, _ := time.Parse(time.RFC3339Nano, events[j].Timestamp)
		return a.Before(b)
	})
	return events, nil
}

func evidenceTimeWithin(e resultEvidence, start, end time.Time) bool {
	at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	return err == nil && !at.Before(start) && !at.After(end)
}

func evidenceHost(e resultEvidence) string {
	if h, _, err := net.SplitHostPort(e.Host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(e.Host)
}

func evidenceMatchesFixture(e resultEvidence, c measurementCase) bool {
	if e.Fixture != "" {
		return e.Fixture == c.Fixture
	}
	return evidenceMatchesHTTPHost(e, c)
}

func evidenceMatchesHTTPHost(e resultEvidence, c measurementCase) bool {
	host, port, err := net.SplitHostPort(e.Host)
	if err != nil {
		return c.Port == 443 && strings.EqualFold(e.Host, c.Host)
	}
	return strings.EqualFold(host, c.Host) && port == strconv.Itoa(c.Port)
}

func recognizedBrowserAgent(agent string) bool {
	return strings.Contains(agent, "Mozilla/") || strings.Contains(agent, "Firefox/") || strings.Contains(agent, "Chrome/") || strings.Contains(agent, "HeadlessChrome/")
}

func sameNegotiation(a, b resultEvidence) bool {
	return a.TLSVersion == b.TLSVersion && a.CipherSuite == b.CipherSuite && reflect.DeepEqual(a.ECHAccepted, b.ECHAccepted) && reflect.DeepEqual(a.Resumed, b.Resumed)
}

func applyNegotiation(run *runRecord, e resultEvidence, c measurementCase) bool {
	run.TLSVersion = e.TLSVersion
	run.CipherSuite = e.CipherSuite
	run.ECHAccepted = e.ECHAccepted
	run.Resumed = e.Resumed
	run.MeasuredUserAgent = e.UserAgent
	match := e.TLSVersion == c.ExpectedTLS && (c.ExpectedCipher == "" || e.CipherSuite == c.ExpectedCipher)
	if c.ExpectedECH != nil {
		match = match && e.ECHAccepted != nil && *e.ECHAccepted == *c.ExpectedECH
	}
	run.ExpectedMatch = boolPointer(match)
	return e.TLSVersion == c.ExpectedTLS && (c.ExpectedCipher == "" || e.CipherSuite == c.ExpectedCipher)
}

func classifyRun(run *runRecord, events []resultEvidence, all map[string]runRecord) {
	c, _ := measurementCaseByID(run.CaseID)
	start, startErr := time.Parse(time.RFC3339Nano, run.StartedUTC)
	end, endErr := time.Parse(time.RFC3339Nano, run.CompletedUTC)
	run.Outcome = "inconclusive"
	if startErr != nil || endErr != nil || end.Before(start) {
		run.Reason = "Invalid registration/completion time window."
		return
	}
	if end.Sub(start) > 2*time.Minute {
		run.Reason = "Run exceeded the two-minute evidence-correlation window; repeat with fresh state."
		return
	}
	var exactHTTP, candidates []resultEvidence
	ambiguous := false
	for _, e := range events {
		if e.ClientIP != run.ClientIP || !evidenceTimeWithin(e, start, end) || !evidenceMatchesFixture(e, c) {
			continue
		}
		if e.Event == "http_result" {
			if e.RunID == run.RunID && evidenceMatchesHTTPHost(e, c) {
				exactHTTP = append(exactHTTP, e)
			} else if e.RunID != "" && e.RunID != run.RunID {
				ambiguous = true
			}
		} else {
			candidates = append(candidates, e)
		}
	}
	for _, other := range all {
		if other.RunID == run.RunID || other.ClientIP != run.ClientIP {
			continue
		}
		otherCase, ok := measurementCaseByID(other.CaseID)
		if !ok || otherCase.Fixture != c.Fixture {
			continue
		}
		a, err := time.Parse(time.RFC3339Nano, other.StartedUTC)
		if err != nil {
			continue
		}
		b := end
		if other.CompletedUTC != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, other.CompletedUTC); err == nil {
				b = parsed
			}
		}
		if a.Before(end) && b.After(start) {
			ambiguous = true
		}
	}
	if len(exactHTTP) > 0 {
		run.Evidence = append(run.Evidence, exactHTTP...)
		chosen := exactHTTP[len(exactHTTP)-1]
		for _, e := range exactHTTP {
			if !sameNegotiation(chosen, e) {
				run.Reason = "Conflicting server HTTP observations share this run ID."
				return
			}
		}
		run.Correlation = "run_id + expected host + client IP + registered time window"
		if !recognizedBrowserAgent(chosen.UserAgent) {
			run.Reason = "Matched HTTP evidence does not identify a browser User-Agent; independent CLI probes are not browser measurements."
			return
		}
		if !applyNegotiation(run, chosen, c) {
			run.Outcome = "fixture_mismatch"
			run.Reason = "Server-negotiated TLS version or cipher does not match the restricted fixture."
			return
		}
		if chosen.Resumed != nil && *chosen.Resumed {
			run.Outcome = "inconclusive"
			run.Reason = "Session resumption violates the fresh-handshake control."
			return
		}
		run.Outcome = "connected"
		run.Reason = "Server recorded the browser's run-tagged HTTP request with the expected TLS parameters."
		switch c.ID {
		case "E1":
			if chosen.ECHAccepted == nil {
				run.Outcome = "inconclusive"
				run.Reason = "Server ECH acceptance flag is missing."
			} else if *chosen.ECHAccepted {
				run.Outcome = "ech_accepted"
			} else {
				run.Outcome = "connected_without_ech"
				run.Reason = "Connection completed, but the server did not accept ECH."
			}
		case "E2":
			if chosen.ECHAccepted == nil {
				run.Outcome = "inconclusive"
				run.Reason = "Server ECH acceptance flag is missing."
			} else if *chosen.ECHAccepted {
				run.Outcome = "unexpected_ech_acceptance"
				run.Reason = "The no-advertisement baseline unexpectedly used accepted ECH; inspect fixture/cache state."
			} else {
				run.Outcome = "connected_no_ech"
				run.Reason = "Expected baseline: request completed without accepted ECH. This does not classify GREASE."
			}
		case "E3":
			if chosen.ECHAccepted == nil {
				run.Outcome = "inconclusive"
				run.Reason = "Server ECH acceptance flag is missing."
			} else if !*chosen.ECHAccepted {
				run.Outcome = "connected_without_ech"
				run.Reason = "Stale-case request completed without accepted ECH; recovery was not demonstrated."
			} else {
				run.Outcome = "ech_accepted_retry_unverified"
				run.RetryEvidence = "Final ECH accepted; initial rejection/retry was not uniquely correlated."
				if !ambiguous {
					chosenTime, _ := time.Parse(time.RFC3339Nano, chosen.Timestamp)
					for _, e := range candidates {
						at, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
						if e.ServerName == "public.tlslab.test" && e.ECHAccepted != nil && !*e.ECHAccepted && e.Success != nil && *e.Success && at.Before(chosenTime) {
							run.Evidence = append(run.Evidence, e)
							run.Outcome = "ech_recovered"
							run.RetryEvidence = "Outer public-name connection with ECH=false preceded the run-tagged inner request with ECH=true. Consistent with authenticated retry; extension/configuration ID and exact retry count are not directly decoded."
						}
					}
				}
			}
		}
		if run.BrowserOutcome != "connected" {
			run.Reason += " Browser reported " + run.BrowserOutcome + "; application delivery must be diagnosed separately from the server-verified TLS exchange."
		}
		return
	}
	if ambiguous {
		run.Reason = "Overlapping runs or another run's request make pre-HTTP evidence attribution ambiguous."
		return
	}
	run.Evidence = candidates
	run.Correlation = "serialized registration window + fixture + server-observed client IP; no HTTP run ID"
	if len(candidates) == 0 {
		run.Reason = "No correlated server handshake or run-tagged HTTP evidence. DNS, connectivity, browser setup or logging may be responsible."
		return
	}
	var positive *resultEvidence
	rejection, certificateFailure := "", ""
	for i := range candidates {
		e := &candidates[i]
		if e.Success != nil && *e.Success {
			if positive != nil && !sameNegotiation(*positive, *e) {
				run.Reason = "Conflicting pre-HTTP handshake outcomes require further correlation."
				return
			}
			positive = e
		} else if e.Error != "" {
			kind := classifiedHandshakeError(e.Error)
			if kind == "certificate_error" {
				certificateFailure = e.Error
			} else if kind != "" {
				rejection = kind
			}
		}
	}
	if positive != nil {
		applyNegotiation(run, *positive, c)
		run.Outcome = "handshake_only"
		run.Reason = "A correlated handshake succeeded, but no matching HTTP request was observed; browser delivery remains unverified."
		return
	}
	if certificateFailure != "" {
		run.Outcome = "infrastructure_error"
		run.Reason = "Certificate-related handshake error: " + certificateFailure
		return
	}
	if rejection != "" {
		run.Outcome = rejection
		run.Reason = "A correlated server handshake explicitly reports a protocol/cipher incompatibility. Generic browser failure alone was not used."
		return
	}
	run.Reason = "Correlated handshake errors do not uniquely establish protocol/cipher incompatibility; inspect the retained errors."
}

func classifiedHandshakeError(message string) string {
	m := strings.ToLower(message)
	for _, term := range []string{"bad certificate", "unknown certificate", "unknown ca", "certificate expired", "certificate verify", "certificate unknown", "certificate authority"} {
		if strings.Contains(m, term) {
			return "certificate_error"
		}
	}
	for _, term := range []string{"unsupported versions", "unsupported protocol", "alert protocol version", "protocol version not supported"} {
		if strings.Contains(m, term) {
			return "rejected_protocol"
		}
	}
	for _, term := range []string{"no cipher suite supported", "no shared cipher", "no cipher suites in common", "no suitable signature algorithm"} {
		if strings.Contains(m, term) {
			return "rejected_cipher_or_signature"
		}
	}
	return ""
}

func (s *resultsStore) results(w http.ResponseWriter, r *http.Request) {
	if !resultMethod(w, r, http.MethodGet) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, err := s.loadRuns()
	if err != nil {
		resultError(w, 500, "run journal unavailable: "+err.Error())
		return
	}
	writeResultJSON(w, 200, resultRunList(runs, r.URL.Query().Get("batch_id"), true))
}

type browserSummary struct {
	BrowserID    string `json:"browser_id"`
	Product      string `json:"product"`
	Version      string `json:"version"`
	Distribution string `json:"distribution"`
	OS           string `json:"os"`
}
type summaryCell struct {
	BrowserID           string         `json:"browser_id"`
	CaseID              string         `json:"case_id"`
	Registered          int            `json:"registered"`
	Completed           int            `json:"completed"`
	Pending             int            `json:"pending"`
	ExpectedRepetitions int            `json:"expected_repetitions"`
	Counts              map[string]int `json:"counts"`
	RunIDs              []string       `json:"run_ids"`
}
type resultSummary struct {
	BatchID    string            `json:"batch_id,omitempty"`
	Browsers   []browserSummary  `json:"browsers"`
	Cases      []measurementCase `json:"cases"`
	Cells      []summaryCell     `json:"cells"`
	Registered int               `json:"registered"`
	Completed  int               `json:"completed"`
}

func buildResultSummary(rows []runRecord, batch string) resultSummary {
	result := resultSummary{BatchID: batch, Browsers: []browserSummary{}, Cases: measurementCases(), Cells: []summaryCell{}}
	browsers := map[string]browserSummary{}
	for _, run := range rows {
		browsers[run.BrowserID] = browserSummary{run.BrowserID, run.BrowserProduct, run.BrowserVersion, run.Distribution, run.OS}
		result.Registered++
		if run.Status == "completed" {
			result.Completed++
		}
	}
	for _, b := range browsers {
		result.Browsers = append(result.Browsers, b)
	}
	sort.Slice(result.Browsers, func(i, j int) bool { return result.Browsers[i].BrowserID < result.Browsers[j].BrowserID })
	for _, b := range result.Browsers {
		for _, c := range result.Cases {
			cell := summaryCell{BrowserID: b.BrowserID, CaseID: c.ID, ExpectedRepetitions: 3, Counts: map[string]int{}, RunIDs: []string{}}
			for _, run := range rows {
				if run.BrowserID == b.BrowserID && run.CaseID == c.ID {
					cell.Registered++
					cell.RunIDs = append(cell.RunIDs, run.RunID)
					if run.Status == "completed" {
						cell.Completed++
						cell.Counts[run.Outcome]++
					} else {
						cell.Pending++
					}
				}
			}
			result.Cells = append(result.Cells, cell)
		}
	}
	return result
}

func (s *resultsStore) summary(w http.ResponseWriter, r *http.Request) {
	if !resultMethod(w, r, http.MethodGet) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, err := s.loadRuns()
	if err != nil {
		resultError(w, 500, "run journal unavailable: "+err.Error())
		return
	}
	batch := r.URL.Query().Get("batch_id")
	writeResultJSON(w, 200, buildResultSummary(resultRunList(runs, batch, false), batch))
}

func csvSafe(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsAny(trimmed[:1], "=+-@") {
		return "'" + value
	}
	return value
}

func (s *resultsStore) export(w http.ResponseWriter, r *http.Request) {
	if !resultMethod(w, r, http.MethodGet) {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" && format != "csv" {
		resultError(w, 400, "format must be jsonl or csv")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, err := s.loadRuns()
	if err != nil {
		resultError(w, 500, "run journal unavailable: "+err.Error())
		return
	}
	rows := resultRunList(runs, r.URL.Query().Get("batch_id"), true)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="browser-results.`+format+`"`)
	if format == "jsonl" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		encoder := json.NewEncoder(w)
		for _, run := range rows {
			if err := encoder.Encode(run); err != nil {
				return
			}
		}
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"run_id", "batch_id", "browser_id", "browser_product", "browser_version", "distribution", "os", "case_id", "repetition", "client_ip", "started_utc", "completed_utc", "outcome", "browser_outcome", "tls_version", "cipher_suite", "ech_accepted", "expected_match", "reason", "retry_evidence", "browser_error", "certificate_sha256", "evidence"})
	for _, run := range rows {
		value := func(p *bool) string {
			if p == nil {
				return ""
			}
			return strconv.FormatBool(*p)
		}
		evidence, _ := json.Marshal(run.Evidence)
		row := []string{run.RunID, run.BatchID, run.BrowserID, run.BrowserProduct, run.BrowserVersion, run.Distribution, run.OS, run.CaseID, strconv.Itoa(run.Repetition), run.ClientIP, run.StartedUTC, run.CompletedUTC, run.Outcome, run.BrowserOutcome, run.TLSVersion, run.CipherSuite, value(run.ECHAccepted), value(run.ExpectedMatch), run.Reason, run.RetryEvidence, run.BrowserError, run.CertificateSHA256, string(evidence)}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		if err := writer.Write(row); err != nil {
			return
		}
	}
	writer.Flush()
}
