package nethsm

import "github.com/borud/nethsm/api"

// GetInfo returns vendor, product and an optional error.
func (s *Session) GetInfo() (*api.InfoData, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return nil, err
	}

	info, resp, err := client.InfoGet(ctx).Execute()
	defer closeBody(resp)
	if err != nil {
		return nil, err
	}
	return info, err
}
