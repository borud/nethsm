package dockerhsm

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/borud/udock"
	"github.com/docker/docker/client"
)

// DockerHSM is a tool for running NetHSM in a docker container for testing.
type DockerHSM struct {
	image          string
	adminPassword  string
	unlockPassword string
	hsmListenPort  int
	containerName  string
	containerID    string
	udock          *udock.Session
	apiURL         string
}

const (
	defaultNetHSMTestingImage = "nitrokey/nethsm:testing"
)

// DockerAvailable is used to determine if docker is available.  This can be used to skip tests.
func DockerAvailable() bool {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return false
	}

	defer cli.Close()

	_, err = cli.Ping(context.Background())
	return err == nil
}

// Create NetHSM docker container.  When this function returns the container
// has been created and the NetHSM is starting.  However it is not necessarily
// ready to serve requests yet.
func Create() (*DockerHSM, error) {
	dockerImage := defaultNetHSMTestingImage

	adminPassword, err := generatePassword(16)
	if err != nil {
		return nil, err
	}

	unlockPassword, err := generatePassword(16)
	if err != nil {
		return nil, err
	}

	hsmListenPort, err := freeListenPort()
	if err != nil {
		return nil, err
	}

	// create docker container
	udock, err := udock.Create()
	if err != nil {
		return nil, err
	}

	err = udock.PullImage(dockerImage)
	if err != nil {
		return nil, err
	}

	containerName := fmt.Sprintf("nethsm-%d", time.Now().UnixNano())

	containerID, err := udock.CreateContainer(dockerImage, containerName, map[string]string{fmt.Sprintf("%d", hsmListenPort): "8443"})
	if err != nil {
		return nil, err
	}

	err = udock.StartContainer(containerID)
	if err != nil {
		err2 := udock.RemoveContainer(containerID)
		if err2 != nil {
			slog.Error("failed to remove container that failed to start", "containerID", containerID, "err", err)
		}
		return nil, err
	}

	apiURL := fmt.Sprintf("https://127.0.0.1:%d/api/v1", hsmListenPort)

	// Block until til NetHSM is up.  When this is run in a unit test we don't need a timeout
	// mechanism for this since the unit test framework has a timeout mechanism, but if you
	// want to extract this code into a library and make use of it for non-testing purposes
	// it may be a good idea to add a timeout mechanism to it to ensure it doesn't get stuck here.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for {
		resp, err := client.Get(apiURL + "/info")
		if err != nil {
			// If an error occurred the NetHSM isn't ready, so we sleep a bit
			// and then go around again.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// a HTTP 200 code means that the NetHSM is ready to serve requests.
		if resp.StatusCode == http.StatusOK {
			break
		}
	}

	return &DockerHSM{
		image:          dockerImage,
		adminPassword:  adminPassword,
		unlockPassword: unlockPassword,
		hsmListenPort:  hsmListenPort,
		containerName:  containerName,
		containerID:    containerID,
		udock:          udock,
		apiURL:         apiURL,
	}, nil
}

// AdminPassword returns the generated admin password.
func (d *DockerHSM) AdminPassword() string {
	return d.adminPassword
}

// UnlockPassword returns the generated unlock password.
func (d *DockerHSM) UnlockPassword() string {
	return d.unlockPassword
}

// APIURL returns the API URL for the NetHSM.
func (d *DockerHSM) APIURL() string {
	return d.apiURL
}

// Shutdown the NetHSM docker container
func (d *DockerHSM) Shutdown() error {
	err := d.udock.RemoveContainer(d.containerID)
	if err != nil {
		return err
	}
	return d.udock.Close()
}
