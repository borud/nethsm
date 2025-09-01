package nethsm

import (
	"io"
	"net/http"
)

// closeBody drains and closes the resp.Body if non-nil
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
