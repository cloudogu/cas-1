package cas

import (
	"net/http"

	"github.com/golang/glog"
	"github.com/patrickmn/go-cache"
	"time"
)

// restClientHandler handles CAS REST Protocol over HTTP Basic Authentication
type restClientHandler struct {
	c       *RestClient
	h       http.Handler
}

// ServeHTTP handles HTTP requests, processes HTTP Basic Authentication over CAS Rest api
// and passes requests up to its child http.Handler.
func (ch *restClientHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if glog.V(2) {
		glog.Infof("cas: handling %v request for %v", r.Method, r.URL)
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"CAS Protected Area\"")
		w.WriteHeader(401)
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
		newAuthenticationResponse, err := ch.authenticate(username, password)
		if err != nil {
			if glog.V(1) {
				glog.Infof("cas: rest authentication failed %v", err)
			}
			w.Header().Set("WWW-Authenticate", "Basic realm=\"CAS Protected Area\"")
			w.WriteHeader(401)
			return
		}
		glog.Infof("Adding new authenticationResponse to cache")
		requestCache.Set(username, newAuthenticationResponse, cache.DefaultExpiration)
		//TODO: Set firstAuthenticatedRequest
		glog.Infof("Setting firstAuthenticatedRequest")
		setFirstAuthenticatedRequest(r, true)
	}
	glog.Infof("Getting authenticationResponse from cache")
	authenticationResponse, keyWasFound = requestCache.Get(username)
	glog.Infof("Setting authenticationResponse to request")
	setAuthenticationResponse(r, authenticationResponse.(*AuthenticationResponse))
	glog.Infof("Serve request")
	ch.h.ServeHTTP(w, r)
	return
}

func (ch *restClientHandler) authenticate(username string, password string) (*AuthenticationResponse, error) {
	tgt, err := ch.c.RequestGrantingTicket(username, password)
	if err != nil {
		return nil, err
	}

	st, err := ch.c.RequestServiceTicket(tgt)
	if err != nil {
		return nil, err
	}

	return ch.c.ValidateServiceTicket(st)
}
