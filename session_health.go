package nethsm

import (
	"fmt"

	"github.com/borud/nethsm/api"
)

// GetHealthState of the NetHSM
func (s *Session) GetHealthState() (api.SystemState, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return "", err
	}

	healthState, resp, err := client.HealthStateGet(ctx).Execute()
	defer closeBody(resp)
	if err != nil {
		return healthState.State, fmt.Errorf("failed to get health state: %w", err)
	}

	return healthState.State, nil
}

// GetHealthReady returns true if the NetHSM is to accept traffic (implies "Operational" state)
func (s *Session) GetHealthReady() (bool, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return false, err
	}

	resp, err := client.HealthReadyGet(ctx).Execute()
	defer closeBody(resp)
	if err != nil {
		if resp.StatusCode == 412 {
			return false, err
		}
		return false, fmt.Errorf("failed to get ready state: %w", err)
	}

	if resp.StatusCode == 200 {
		return true, nil
	}

	return false, fmt.Errorf("unknown response, code is %d", resp.StatusCode)
}

// GetHealthAlive returns true if the NetHSM is alive, but not ready to accept
// traffic (implies Locked or Unprovisioned)
func (s *Session) GetHealthAlive() (bool, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return false, err
	}

	resp, err := client.HealthAliveGet(ctx).Execute()
	defer closeBody(resp)
	if err != nil {
		if resp.StatusCode == 412 {
			return false, err
		}
		return false, fmt.Errorf("failed to get alive state: %w", err)
	}

	if resp.StatusCode == 200 {
		return true, nil
	}

	return false, fmt.Errorf("unknown response, code is %d", resp.StatusCode)
}
