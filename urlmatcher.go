package caddypaw

import (
	"fmt"
	"strings"
)

const (
	matcherTypePathPrefix = "path_prefix"
)

type urlMatcher struct {
	MatcherType string `json:"matcher_type"`
	Pattern     string `json:"pattern"`
}

func urlMatcherFromStr(s string) (*urlMatcher, error) {
	ss := strings.SplitN(s, ":", 2)
	if len(ss) != 2 {
		return nil, fmt.Errorf("url matcher format error: %s", s)
	}

	if ss[0] != matcherTypePathPrefix {
		return nil, fmt.Errorf("unsupported matcher type: %s", ss[0])
	}

	return &urlMatcher{
		MatcherType: ss[0],
		Pattern:     ss[1],
	}, nil
}
