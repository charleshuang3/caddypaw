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
}

// NewWAF compiles the provided configuration and initializes a new WAF instance.
func NewWAF(cfg *Config, logger *zap.Logger) (*WAF, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	corazaCfg, err := cfg.BuildCorazaConfig(logger)
	if err != nil {
		return nil, err
	}

	wafInstance, err := coraza.NewWAF(corazaCfg)
	if err != nil {
		return nil, err
	}

	return &WAF{
		corazaWAF: wafInstance,
		logger:    logger,
	}, nil
}

// ProcessRequest evaluates an HTTP request against the compiled WAF rules.
// It manages the entire Coraza transaction lifecycle and rewinds/refills r.Body
// when body inspection is enabled.
func (w *WAF) ProcessRequest(r *http.Request) (interrupted bool, status int, ruleID int, err error) {
	tx := w.corazaWAF.NewTransaction()
	defer func() { _ = tx.Close() }()
	defer tx.ProcessLogging()

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

	// Evaluate phase 1 (request headers)
	if it := tx.ProcessRequestHeaders(); it != nil {
		return formatInterruption(it)
	}

	// Read and buffer request body if accessible
	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, readErr := tx.ReadRequestBodyFrom(r.Body)
		if readErr != nil {
			return false, 0, 0, readErr
		}
		if it != nil {
			return formatInterruption(it)
		}

		rbr, readerErr := tx.RequestBodyReader()
		if readerErr != nil {
			return false, 0, 0, readerErr
		}
		bufferedBytes, copyErr := io.ReadAll(rbr)
		if copyErr != nil {
			return false, 0, 0, copyErr
		}
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bufferedBytes), r.Body))
	}

	// Phase 2 evaluation must run for every request (query-string-only attacks
	// hit phase-2 rules with an empty body), mirroring coraza-caddy.
	it, processErr := tx.ProcessRequestBody()
	if processErr != nil {
		return false, 0, 0, processErr
	}
	if it != nil {
		return formatInterruption(it)
	}

	return false, 0, 0, nil
}

func formatInterruption(it *types.Interruption) (bool, int, int, error) {
	if it == nil {
		return false, 0, 0, nil
	}
	// v1: all disruptions (deny/drop/redirect) are mapped to a uniform 403-style
	// block. deny honors its declared status; drop/redirect collapse to 403.
	status := it.Status
	switch it.Action {
	case "deny":
		if status == 0 {
			status = http.StatusForbidden
		}
	default: // "drop", "redirect", and any future disruptive action
		status = http.StatusForbidden
	}
	return true, status, it.RuleID, nil
}
