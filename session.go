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
			TLSClientConfig:     config.tlsConfig(),
			DialContext:         dialer,
			DisableKeepAlives:   true,
			MaxIdleConnsPerHost: 2,
			MaxConnsPerHost:     4,
			IdleConnTimeout:     15 * time.Second,
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
