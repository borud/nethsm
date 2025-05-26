package nethsm

import (
	"fmt"

	"github.com/borud/nethsm/api"
)

// Lock the NetHSM
func (s *Session) Lock() error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	resp, err := client.LockPost(ctx).Execute()
	defer closeBody(resp)
	if err != nil {
		return fmt.Errorf("failed to lock NetHSM instance: %w", err)
	}
	return nil
}

// UnLock the NetHSM
func (s *Session) UnLock(unlockPassphrase string) error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	resp, err := client.UnlockPost(ctx).
		UnlockRequestData(*api.NewUnlockRequestData(unlockPassphrase)).
		Execute()
	defer closeBody(resp)
	if err != nil {
		return fmt.Errorf("failed to unlock NetHSM instance: %w", err)
	}
	return nil
}
