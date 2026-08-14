package aikido

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadSBOM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/oauth/token":
			clientID, clientSecret, ok := req.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, "client", clientID)
			assert.Equal(t, "secret", clientSecret)
			assert.Equal(t, http.MethodPost, req.Method)

			body, err := io.ReadAll(req.Body)
			if !assert.NoError(t, err) {
				return
			}

			assert.JSONEq(t, `{"grant_type":"client_credentials"}`, string(body))

			_, err = rw.Write([]byte(`{"access_token":"token"}`))
			assert.NoError(t, err)

		case "/api/public/v1/repositories/code/repo-code/licenses/export":
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, "sbom", req.URL.Query().Get("format"))
			assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))

			_, err := rw.Write([]byte(`{"bomFormat":"CycloneDX"}`))
			assert.NoError(t, err)

		default:
			http.NotFound(rw, req)
		}
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "client", "secret", server.Client())
	sbom, err := client.DownloadSBOM(context.Background(), "repo-code")
	require.NoError(t, err)
	assert.JSONEq(t, `{"bomFormat":"CycloneDX"}`, string(sbom))
}

func TestDownloadSBOMTokenFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "invalid credentials", http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "client", "secret", server.Client())
	_, err := client.DownloadSBOM(context.Background(), "repo-code")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
}

func TestDownloadSBOMExportFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/oauth/token" {
			_, err := rw.Write([]byte(`{"access_token":"token"}`))
			assert.NoError(t, err)

			return
		}

		http.Error(rw, "repository not found", http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "client", "secret", server.Client())
	_, err := client.DownloadSBOM(context.Background(), "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 404")
}

func TestDownloadSBOMMissingToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, err := rw.Write([]byte(`{}`))
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.URL, "client", "secret", server.Client())
	_, err := client.DownloadSBOM(context.Background(), "repo-code")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not contain an access token")
}
