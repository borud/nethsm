package nethsm

import (
	"context"
	"crypto/tls"
	"net/http"

	api "github.com/borud/nethsm/api"
)

// Session is a NetHSM session.
type Session struct {
	Namespace     string
	Username      string
	Password      string
	APIURL        string
	SkipTLSVerify bool
}

// newClientAndContext is a convenience function that is used to get a usable REST client and a context object.
func (s *Session) newClientAndContext() (*api.DefaultAPIService, context.Context) {
	// Create the HTTP client depending on parameters
	httpClient := http.DefaultClient
	if s.SkipTLSVerify {
		httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}

	// Set the API endpoint URL and the http client
	config := api.NewConfiguration()
	config.Servers = api.ServerConfigurations{{URL: s.APIURL}}
	config.HTTPClient = httpClient

	// Cretae a
	return api.NewAPIClient(config).DefaultAPI, context.WithValue(context.Background(), api.ContextBasicAuth, api.BasicAuth{
		UserName: s.Username,
		Password: s.Password,
	})
}
