package nethsm

import (
	"net/http"
)

// closeBody closes the resp.Body if non-nil
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
}
