package nethsm

import (
	"context"
	"net/http"
	"time"

	api "github.com/borud/nethsm/api"
)

// Session is a NetHSM session.
type Session struct {
	config  Config
	client  *api.DefaultAPIService
	authCtx context.Context
}

// NewSession creates a news session.
func NewSession(config Config) (*Session, error) {
	dialer, err := config.newDialContextFunc()
	if err != nil {
		return nil, err
	}

	// Create the HTTP client depending on parameters
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     config.tlsConfig(),
			DialContext:         dialer,
			DisableKeepAlives:   true,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 4,
			MaxConnsPerHost:     10,
			IdleConnTimeout:     15 * time.Second,

			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 120 * time.Second, // some calls can take a long time
			ResponseHeaderTimeout: 120 * time.Second, // some calls can take a long time
		},
	}

	// configure the OpenAPI client
	apiConfig := api.NewConfiguration()
	apiConfig.Servers = api.ServerConfigurations{{URL: config.APIURL}}
	apiConfig.HTTPClient = httpClient

	client := api.NewAPIClient(apiConfig).DefaultAPI

	return &Session{
		config: config,
		client: client,
		authCtx: context.WithValue(context.Background(), api.ContextBasicAuth, api.BasicAuth{
			UserName: config.Username,
			Password: config.Password,
		}),
	}, err
}
