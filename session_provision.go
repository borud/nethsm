package nethsm

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/borud/nethsm/api"
)

// Provision the NetHSM and set unlock and admin passphrases.
func (s *Session) Provision(unlockPass string, adminPass string) error {
	slog.Debug("provisioning NetHSM, this may take some time", "apiURL", s.config.APIURL)
	resp, err := s.client.ProvisionPost(s.authCtx).
		ProvisionRequestData(
			*api.NewProvisionRequestData(
				unlockPass,
				adminPass,
				time.Time{})).Execute()
	defer closeBody(resp)
	if err != nil {
		return fmt.Errorf("failed to provision NetHSM [%s]: %w", s.config.APIURL, err)
	}
	return nil
}
