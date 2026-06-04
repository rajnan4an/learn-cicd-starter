package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-api-key")

	apiKey, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := "my-secret-api-key"

	if apiKey != expected {
		t.Errorf("expected api key %q, got %q", expected, apiKey)
	}
}

func TestGetAPIKey_NoAuthorizationHeader(t *testing.T) {
	headers := http.Header{}

	apiKey, err := GetAPIKey(headers)

	if err == nil {
		t.Fatal("expected an error but got nil")
	}

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}

	if apiKey != "" {
		t.Errorf("expected empty api key, got %q", apiKey)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer token123")

	apiKey, err := GetAPIKey(headers)

	if err == nil {
		t.Fatal("expected an error but got nil")
	}

	expectedErr := "malformed authorization header"

	if err.Error() != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, err.Error())
	}

	if apiKey != "" {
		t.Errorf("expected empty api key, got %q", apiKey)
	}
}
