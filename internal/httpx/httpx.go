// Package httpx holds small shared HTTP helpers used across wisp's clients.
package httpx

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrorFromResponse builds an error from a non-success HTTP response, appending a
// bounded snippet of the body for context (omitted when the body is empty).
func ErrorFromResponse(resp *http.Response) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if s := strings.TrimSpace(string(snippet)); s != "" {
		return fmt.Errorf("status %d: %s", resp.StatusCode, s)
	}
	return fmt.Errorf("status %d", resp.StatusCode)
}
