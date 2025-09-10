package nethsm

import (
	"context"
	"net/http"

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
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = defaultMaxIdleConns
	}

	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = defaultMaxIdleConnsPerHost
	}

	if config.IdleConnTimeout == 0 {
		config.IdleConnTimeout = defaultIdleConnTimeout
	}

	if config.TLSHandshakeTimeout == 0 {
		config.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	}

	if config.ExpectContinueTimeout == 0 {
		config.ExpectContinueTimeout = defaultExpectContinueTimeout
	}

	if config.ResponseHeaderTimeout == 0 {
		config.ResponseHeaderTimeout = defaultResponseHeaderTimeout
	}

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
			DisableKeepAlives:   config.DisableKeepAlives,
			MaxIdleConns:        config.MaxIdleConns,
			MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
			MaxConnsPerHost:     config.MaxIdleConns,
			IdleConnTimeout:     config.IdleConnTimeout,

			TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
			ExpectContinueTimeout: config.ExpectContinueTimeout,
			ResponseHeaderTimeout: config.ResponseHeaderTimeout,
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
