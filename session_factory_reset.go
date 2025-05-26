package nethsm

import "errors"

// FactoryReset performs a factory reset on the NetHSM.  Use with care!
func (s *Session) FactoryReset() error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	resp, err := client.SystemFactoryResetPost(ctx).Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(err, asError(resp))
	}

	return nil
}
