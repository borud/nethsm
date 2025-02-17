package dockerhsm

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDockerHSM(t *testing.T) {
	if !DockerAvailable() {
		t.Skip("docker not available, skipping test")
	}

	dh, err := Create()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, dh.Shutdown())
	}()

	_, err = url.Parse(dh.APIURL())
	require.NoError(t, err)
	require.NotEmpty(t, dh.AdminPassword())
	require.NotEmpty(t, dh.UnlockPassword())
}
