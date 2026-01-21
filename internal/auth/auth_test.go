package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		shouldError bool
		expectedErr error
	}{
		{
			name:        "valid API key",
			headers:     http.Header{"Authorization": []string{"ApiKey test-key-123"}},
			expectedKey: "test-key-123",
			shouldError: false,
		},
		{
			name:        "no authorization header",
			headers:     http.Header{},
			expectedKey: "",
			shouldError: true,
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "empty authorization header",
			headers:     http.Header{"Authorization": []string{""}},
			expectedKey: "",
			shouldError: true,
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed header - missing ApiKey prefix",
			headers:     http.Header{"Authorization": []string{"Bearer test-key-123"}},
			expectedKey: "",
			shouldError: true,
		},
		{
			name:        "malformed header - no space",
			headers:     http.Header{"Authorization": []string{"test-key-123"}},
			expectedKey: "",
			shouldError: true,
		},
		{
			name:        "malformed header - only ApiKey prefix",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			shouldError: true,
		},
		{
			name:        "API key with special characters",
			headers:     http.Header{"Authorization": []string{"ApiKey test-key_with.special@chars"}},
			expectedKey: "test-key_with.special@chars",
			shouldError: false,
		},
		{
			name:        "API key with multiple spaces",
			headers:     http.Header{"Authorization": []string{"ApiKey test-key extra-stuff"}},
			expectedKey: "test-key",
			shouldError: false,
		},
		{
			name:        "case sensitive - lowercase apikey",
			headers:     http.Header{"Authorization": []string{"apikey test-key-123"}},
			expectedKey: "",
			shouldError: true,
		},
		{
			name:        "API key with whitespace",
			headers:     http.Header{"Authorization": []string{"ApiKey test key"}},
			expectedKey: "test",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				if tt.expectedErr != nil && err != tt.expectedErr {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
