// Copyright 2026 CaddyPAW Authors
// Portions Copyright The Coraza Authors (Apache-2.0 License)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package waf

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"go.uber.org/zap"
)

// WAF wraps a Coraza WAF instance.
type WAF struct {
	corazaWAF coraza.WAF
	logger    *zap.Logger
	// detectOnly reports whether the rule engine was forced to DetectionOnly.
	// Such an instance never interrupts a request; matches are only reported.
	detectOnly bool
}

// Result describes the outcome of a WAF evaluation.
type Result struct {
	// Blocked reports whether the request was interrupted. Always false for
	// detect-only instances.
	Blocked bool
	// Status is the HTTP status to return when Blocked is true.
	Status int
	// RuleID is the rule that caused the interruption.
	RuleID int
	// Detected lists, in evaluation order, the IDs of every rule that matched
	// during the transaction. It is populated for every evaluation, so callers that
	// observe a request instead of blocking it (after_auth phase1_only and skip)
	// still get a rule ID even when the engine interrupted.
	Detected []int
	// ReportID is the single rule ID that represents the transaction for the ban
	// pipeline: the last matched rule that carries a message. The OWASP CRS emits
	// a large number of message-less tagging rules after the real attack rules,
	// so "last match" alone would report a meaningless ID.
	ReportID int
}

// ReportRuleID returns the single rule ID that should be reported for this
// result, or 0 when nothing matched. An interruption wins; otherwise the rule
// selected by collectDetected is used, falling back to the last matched rule.
func (r Result) ReportRuleID() int {
	if r.Blocked && r.RuleID != 0 {
		return r.RuleID
	}
	if r.ReportID != 0 {
		return r.ReportID
	}
	if n := len(r.Detected); n > 0 {
		return r.Detected[n-1]
	}
	return 0
}

// NewWAF compiles the provided configuration and initializes a new WAF instance.
func NewWAF(cfg *Config, logger *zap.Logger) (*WAF, error) {
	return newWAF(cfg, logger, false)
}

// NewWAFDetectOnly compiles the provided configuration with the rule engine
// forced to DetectionOnly: rules are still evaluated so that matches can be
// logged and reported, but requests are never blocked.
func NewWAFDetectOnly(cfg *Config, logger *zap.Logger) (*WAF, error) {
	return newWAF(cfg, logger, true)
}

func newWAF(cfg *Config, logger *zap.Logger, detectOnly bool) (*WAF, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	corazaCfg, err := cfg.buildCorazaConfig(logger, detectOnly)
	if err != nil {
		return nil, err
	}

	wafInstance, err := coraza.NewWAF(corazaCfg)
	if err != nil {
		return nil, err
	}

	return &WAF{
		corazaWAF:  wafInstance,
		logger:     logger,
		detectOnly: detectOnly,
	}, nil
}

// ProcessRequest evaluates an HTTP request against the compiled WAF rules.
// It manages the entire Coraza transaction lifecycle and rewinds/refills r.Body
// when body inspection is enabled.
func (w *WAF) ProcessRequest(r *http.Request) (Result, error) {
	tx := w.newTransaction(r)
	defer func() { _ = tx.Close() }()
	defer tx.ProcessLogging()

	if res, stop, err := w.processRequestHeaders(tx); stop || err != nil {
		return res, err
	}
	if res, stop, err := w.processRequestBody(tx, r); stop || err != nil {
		return res, err
	}
	return collectDetected(tx), nil
}

// ProcessRequestPhase1 evaluates only phase 1 (connection, URI and request
// headers) against the compiled WAF rules. The request body is neither read
// nor buffered, so callers that must avoid the cost of body inspection can use
// this instead of ProcessRequest.
func (w *WAF) ProcessRequestPhase1(r *http.Request) (Result, error) {
	tx := w.newTransaction(r)
	defer func() { _ = tx.Close() }()
	defer tx.ProcessLogging()

	if res, stop, err := w.processRequestHeaders(tx); stop || err != nil {
		return res, err
	}
	return collectDetected(tx), nil
}

// newTransaction creates a Coraza transaction and feeds it the connection,
// URI and header metadata of r.
func (w *WAF) newTransaction(r *http.Request) types.Transaction {
	tx := w.corazaWAF.NewTransaction()

	// Parse client IP and port
	clientIP := r.RemoteAddr
	clientPort := 0
	if host, portStr, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
		clientIP = host
		if p, convErr := strconv.Atoi(portStr); convErr == nil {
			clientPort = p
		}
	}
	tx.ProcessConnection(clientIP, clientPort, "", 0)

	// Process URI
	uri := ""
	if r.URL != nil {
		uri = r.URL.String()
	}
	if uri == "" {
		uri = r.RequestURI
	}
	if uri == "" {
		uri = "/"
	}
	tx.ProcessURI(uri, r.Method, r.Proto)

	// Set ServerName and Host header
	if r.Host != "" {
		serverName := r.Host
		if h, _, splitErr := net.SplitHostPort(r.Host); splitErr == nil {
			serverName = h
		}
		tx.SetServerName(serverName)
		tx.AddRequestHeader("Host", r.Host)
	}

	// Add request headers
	for k, vv := range r.Header {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}

	return tx
}

// processRequestHeaders evaluates phase 1 (request headers). The second return
// value reports whether the caller must stop evaluating the request.
func (w *WAF) processRequestHeaders(tx types.Transaction) (Result, bool, error) {
	it := tx.ProcessRequestHeaders()
	if it == nil || w.detectOnly {
		return Result{}, false, nil
	}
	return interruptionResult(tx, it), true, nil
}

// processRequestBody buffers and evaluates the request body (phase 2). The
// second return value reports whether the caller must stop evaluating the
// request.
func (w *WAF) processRequestBody(tx types.Transaction, r *http.Request) (Result, bool, error) {
	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, readErr := tx.ReadRequestBodyFrom(r.Body)
		if readErr != nil {
			return Result{}, true, readErr
		}
		if it != nil && !w.detectOnly {
			return interruptionResult(tx, it), true, nil
		}

		rbr, readerErr := tx.RequestBodyReader()
		if readerErr != nil {
			return Result{}, true, readerErr
		}
		bufferedBytes, copyErr := io.ReadAll(rbr)
		if copyErr != nil {
			return Result{}, true, copyErr
		}
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bufferedBytes), r.Body))
	}

	// Phase 2 evaluation must run for every request (query-string-only attacks
	// hit phase-2 rules with an empty body), mirroring coraza-caddy.
	it, processErr := tx.ProcessRequestBody()
	if processErr != nil {
		return Result{}, true, processErr
	}
	if it != nil && !w.detectOnly {
		return interruptionResult(tx, it), true, nil
	}

	return Result{}, false, nil
}

// interruptionResult maps a Coraza interruption to a Result.
//
// v1: all disruptions (deny/drop/redirect) are mapped to a uniform 403-style
// block. deny honors its declared status; drop/redirect collapse to 403.
//
// The matched rules are collected as well, even though a blocking caller ignores
// them: callers that only *observe* a request (after_auth phase1_only and skip
// keep the 401 challenge) still need the rule ID for the /logerr report.
func interruptionResult(tx types.Transaction, it *types.Interruption) Result {
	status := it.Status
	switch it.Action {
	case "deny":
		if status == 0 {
			status = http.StatusForbidden
		}
	default: // "drop", "redirect", and any future disruptive action
		status = http.StatusForbidden
	}
	res := Result{Blocked: true, Status: status, RuleID: it.RuleID}
	if detected := collectDetected(tx); len(detected.Detected) > 0 {
		res.Detected = detected.Detected
		res.ReportID = detected.ReportID
	}
	return res
}

// collectDetected gathers the IDs of all rules that matched the transaction and
// picks the one worth reporting.
func collectDetected(tx types.Transaction) Result {
	rules := tx.MatchedRules()
	if len(rules) == 0 {
		return Result{}
	}

	detected := make([]int, 0, len(rules))
	reportID := 0
	for _, rule := range rules {
		id := rule.Rule().ID()
		detected = append(detected, id)
		// The OWASP CRS follows each attack rule with message-less tagging rules
		// (e.g. 9xxxx3/9xxxx4) and closes with the anomaly aggregator (949110),
		// which does carry a message. Keeping the last message-bearing rule yields
		// the same ID that an interruption would have reported.
		if rule.Message() != "" {
			reportID = id
		}
	}
	if reportID == 0 {
		// Rules without a msg (e.g. hand-written test rules) still need a report.
		reportID = detected[len(detected)-1]
	}

	return Result{Detected: detected, ReportID: reportID}
}
