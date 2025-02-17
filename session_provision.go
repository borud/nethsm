package nethsm

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/borud/nethsm/api"
)

// Provision the NetHSM and set unlock and admin passphrases.
func (s *Session) Provision(unlockPass string, adminPass string) error {
	slog.Debug("provisioning NetHSM, this may take some time", "apiURL", s.APIURL)
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}
	_, err = client.ProvisionPost(ctx).
		ProvisionRequestData(
			*api.NewProvisionRequestData(
				unlockPass,
				adminPass,
				time.Time{})).Execute()
	if err != nil {
		return fmt.Errorf("failed to provision NetHSM [%s]: %w", s.APIURL, err)
	}
	return nil
}
