package caddypaw

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_urlMatcherFromStr_Success(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    *urlMatcher
		expectedErr bool
	}{
		{
			name:  "valid path_prefix matcher",
			input: "path_prefix:/foo",
			expected: &urlMatcher{
				MatcherType: matcherTypePathPrefix,
				Pattern:     "/foo",
			},
			expectedErr: false,
		},
		{
			name:  "valid path_prefix matcher with multiple slashes",
			input: "path_prefix:/foo/bar/baz",
			expected: &urlMatcher{
				MatcherType: matcherTypePathPrefix,
				Pattern:     "/foo/bar/baz",
			},
			expectedErr: false,
		},
		{
			name:  "valid path_prefix matcher with empty pattern",
			input: "path_prefix:",
			expected: &urlMatcher{
				MatcherType: matcherTypePathPrefix,
				Pattern:     "",
			},
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := urlMatcherFromStr(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, matcher)
		})
	}
}

func Test_urlMatcherFromStr_Error(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedErr string
	}{
		{
			name:        "invalid format - no colon",
			input:       "path_prefix/foo",
			expectedErr: "url matcher format error: path_prefix/foo",
		},
		{
			name:        "invalid format - empty string",
			input:       "",
			expectedErr: "url matcher format error: ",
		},
		{
			name:        "unsupported matcher type",
			input:       "unsupported:/foo",
			expectedErr: "unsupported matcher type: unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := urlMatcherFromStr(tt.input)
			assert.Error(t, err)
			assert.Nil(t, matcher)
			assert.EqualError(t, err, tt.expectedErr)
		})
	}
}
