package nethsm

import "github.com/borud/nethsm/api"

// GetInfo returns vendor, product and an optional error.
func (s *Session) GetInfo() (*api.InfoData, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return nil, err
	}

	res, _, err := client.InfoGet(ctx).Execute()
	if err != nil {
		return nil, err
	}
	return res, err
}
