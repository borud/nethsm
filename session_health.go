package nethsm

import (
	"fmt"

	"github.com/borud/nethsm/api"
)

// GetHealthState of the NetHSM
func (s *Session) GetHealthState() (api.SystemState, error) {
	client, ctx := s.newClientAndContext()

	response, _, err := client.HealthStateGet(ctx).Execute()
	if err != nil {
		return response.State, fmt.Errorf("failed to get health state: %w", err)
	}

	return response.State, nil
}

// GetHealthReady returns true if the NetHSM is to accept traffic (implies "Operational" state)
func (s *Session) GetHealthReady() (bool, error) {
	client, ctx := s.newClientAndContext()

	response, err := client.HealthReadyGet(ctx).Execute()
	if err != nil {
		if response.StatusCode == 412 {
			return false, err
		}
		return false, fmt.Errorf("failed to get ready state: %w", err)
	}

	if response.StatusCode == 200 {
		return true, nil
	}

	return false, fmt.Errorf("unknown response, code is %d", response.StatusCode)
}

// GetHealthAlive returns true if the NetHSM is alive, but not ready to accept
// traffic (implies Locked or Unprovisioned)
func (s *Session) GetHealthAlive() (bool, error) {
	client, ctx := s.newClientAndContext()

	response, err := client.HealthAliveGet(ctx).Execute()
	if err != nil {
		if response.StatusCode == 412 {
			return false, err
		}
		return false, fmt.Errorf("failed to get alive state: %w", err)
	}

	if response.StatusCode == 200 {
		return true, nil
	}

	return false, fmt.Errorf("unknown response, code is %d", response.StatusCode)
}
