package helper

import (
        "bytes"
        "io"
        "net/http"
        "testing"
)

func testResponseStatus(t *testing.T, resp *http.Response, expectedStatusCode int) {
        if resp.StatusCode != expectedStatusCode {
                body := new(bytes.Buffer)
                io.Copy(body, resp.Body)
                resp.Body.Close()

                t.Fatalf("Expected status %d, got %d. Body\n\n%s", 
                        expectedStatusCode, resp.StatusCode, body.String())
        }
}