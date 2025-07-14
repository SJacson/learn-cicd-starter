package auth

import (
	"net/http"
	"testing"
	"errors"
)

func TestGetAPIKey(t *testing.T) {
	ErrMalformedHeader := errors.New("malformed authorization header")
	tests := []struct {
		name          string
		headers       http.Header
		want   string
		expectedError error
	}{
		{
			name:          "no header",
			headers:       http.Header{},
			want:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			want:   "",
			expectedError: ErrMalformedHeader,
		},
		{
			name: "malformed header - no token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:   "",
			expectedError: ErrMalformedHeader,
		},
		{
			name: "valid header",
			headers: http.Header{
				"Authorization": []string{"ApiKey validtoken123"},
			},
			want:   "validtoken123",
			expectedError: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if key != tc.want {
				t.Errorf("Expected key %q, got %q", tc.want, key)
			}

			if (err != nil && tc.expectedError == nil) ||
				(err == nil && tc.expectedError != nil) ||
				(err != nil && tc.expectedError != nil && err.Error() != tc.expectedError.Error()) {
				t.Errorf("Expected error %v, got %v", tc.expectedError, err)
			}
		})
	}
}
