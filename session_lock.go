package nethsm

import (
	"fmt"

	"github.com/borud/nethsm/api"
)

// Lock the NetHSM
func (s *Session) Lock() error {
	resp, err := s.client.LockPost(s.authCtx).Execute()
	defer closeBody(resp)
	if err != nil {
		return fmt.Errorf("failed to lock NetHSM instance: %w", err)
	}
	return nil
}

// UnLock the NetHSM
func (s *Session) UnLock(unlockPassphrase string) error {
	resp, err := s.client.UnlockPost(s.authCtx).
		UnlockRequestData(*api.NewUnlockRequestData(unlockPassphrase)).
		Execute()
	defer closeBody(resp)
	if err != nil {
		return fmt.Errorf("failed to unlock NetHSM instance: %w", err)
	}
	return nil
}
