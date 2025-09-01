package nethsm

import "errors"

// FactoryReset performs a factory reset on the NetHSM.  Use with care!
func (s *Session) FactoryReset() error {
	resp, err := s.client.SystemFactoryResetPost(s.authCtx).Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(err, asError(resp))
	}

	return nil
}
