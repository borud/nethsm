package nethsm

import (
	"fmt"

	"github.com/borud/nethsm/api"
)

// Lock the NetHSM
func (s *Session) Lock() error {
	client, ctx := s.newClientAndContext()

	_, err := client.LockPost(ctx).Execute()
	if err != nil {
		return fmt.Errorf("failed to lock NetHSM instance: %w", err)
	}
	return nil
}

// UnLock the NetHSM
func (s *Session) UnLock(unlockPassphrase string) error {
	client, ctx := s.newClientAndContext()

	_, err := client.UnlockPost(ctx).
		UnlockRequestData(*api.NewUnlockRequestData(unlockPassphrase)).
		Execute()
	if err != nil {
		return fmt.Errorf("failed to unlock NetHSM instance: %w", err)
	}
	return nil
}
