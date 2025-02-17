package nethsm

import (
	"fmt"
)

// AddNamespace creates a namespace identified by name
func (s *Session) AddNamespace(name string) error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	_, err = client.NamespacesNamespaceIDPut(ctx, name).Execute()
	if err != nil {
		return fmt.Errorf("failed to create namespace [%s]: %w", name, err)
	}
	return nil
}

// ListNamespaces lists the available namespaces
func (s *Session) ListNamespaces() ([]string, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return nil, err
	}

	namespaces, _, err := client.NamespacesGet(ctx).Execute()
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
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	_, err = client.NamespacesNamespaceIDDelete(ctx, name).Execute()
	if err != nil {
		return fmt.Errorf("failed to delete namespace [%s]: %w", name, err)
	}

	return nil
}
