package cas

import (
	"net/http"

	"github.com/golang/glog"
	"github.com/patrickmn/go-cache"
	"time"
)

// restClientHandler handles CAS REST Protocol over HTTP Basic Authentication
type restClientHandler struct {
	restClient *RestClient
	handler    http.Handler
}

// ServeHTTP handles HTTP requests, processes HTTP Basic Authentication over CAS Rest api
// and passes requests up to its child http.Handler.
func (restClientHandler *restClientHandler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if glog.V(2) {
		glog.Infof("cas: handling %v request for %v", request.Method, request.URL)
	}

	username, password, ok := request.BasicAuth()
	if !ok {
		responseWriter.Header().Set("WWW-Authenticate", "Basic realm=\"CAS Protected Area\"")
		responseWriter.WriteHeader(401)
		return
	}

	// TODO we should implement a short cache to avoid hitting cas server on every request
	// the cache could use the authorization header as key and the authenticationResponse as value
	glog.Infof("Setting up request cache")
	requestCache := cache.New(2*time.Minute, 5*time.Minute)
	glog.Infof("Checking if authenticationResponse is already in cache")
	authenticationResponse, keyWasFound := requestCache.Get(username)
	if !keyWasFound {
		glog.Infof("authenticationResponse was not already in cache; creating new one...")
		newAuthenticationResponse, err := restClientHandler.authenticate(username, password)
		if err != nil {
			if glog.V(1) {
				glog.Infof("cas: rest authentication failed %v", err)
			}
			responseWriter.Header().Set("WWW-Authenticate", "Basic realm=\"CAS Protected Area\"")
			responseWriter.WriteHeader(401)
			return
		}
		glog.Infof("Adding new authenticationResponse to cache")
		requestCache.Set(username, newAuthenticationResponse, cache.DefaultExpiration)
		//TODO: Set firstAuthenticatedRequest
		glog.Infof("Setting firstAuthenticatedRequest")
		setFirstAuthenticatedRequest(request, true)
	}
	glog.Infof("Getting authenticationResponse from cache")
	authenticationResponse, keyWasFound = requestCache.Get(username)
	glog.Infof("Setting authenticationResponse to request")
	setAuthenticationResponse(request, authenticationResponse.(*AuthenticationResponse))
	glog.Infof("Serve request")
	restClientHandler.handler.ServeHTTP(responseWriter, request)
	return
}

func (ch *restClientHandler) authenticate(username string, password string) (*AuthenticationResponse, error) {
	tgt, err := ch.restClient.RequestGrantingTicket(username, password)
	if err != nil {
		return nil, err
	}

	st, err := ch.restClient.RequestServiceTicket(tgt)
	if err != nil {
		return nil, err
	}

	return ch.restClient.ValidateServiceTicket(st)
}
