package nethsm

import (
	"fmt"
)

// AddNamespace creates a namespace identified by name
func (s *Session) AddNamespace(name string) error {
	resp, err := s.client.NamespacesNamespaceIDPut(s.authCtx, name).Execute()
	defer closeBody(resp)
	if err != nil {
		return fmt.Errorf("failed to create namespace [%s]: %w", name, err)
	}
	return nil
}

// ListNamespaces lists the available namespaces
func (s *Session) ListNamespaces() ([]string, error) {
	namespaces, resp, err := s.client.NamespacesGet(s.authCtx).Execute()
	defer closeBody(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	nslist := make([]string, len(namespaces))

	for i, nsitem := range namespaces {
		nslist[i] = nsitem.Id
	}

	return nslist, nil
}

// DeleteNamespace removes a namespace identified by name.
func (s *Session) DeleteNamespace(name string) error {
	resp, err := s.client.NamespacesNamespaceIDDelete(s.authCtx, name).Execute()
	defer closeBody(resp)
	if err != nil {
		return fmt.Errorf("failed to delete namespace [%s]: %w", name, err)
	}

	return nil
}
