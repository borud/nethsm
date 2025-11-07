package nethsm

import (
	"io"
	"log/slog"
	"net/http"
	"os"
)

// closeBody drains and closes the resp.Body if non-nil
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// removeFile cleans up temporary files and logs if this doesn't succeed.
func removeFile(file *os.File) {
	slog.Info("removing file", "filename", file.Name())
	err := os.Remove(file.Name())
	if err != nil {
		slog.Error("failed to remove file", "filename", file.Name(), "err", err)
	}
}
