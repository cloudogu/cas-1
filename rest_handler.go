package cas

import (
	"net/http"

	"github.com/golang/glog"
	"github.com/patrickmn/go-cache"
)

// restClientHandler handles CAS REST Protocol over HTTP Basic Authentication
type restClientHandler struct {
	c *RestClient
	h http.Handler
	cache *cache.Cache
	forwardUnauthenticatedRequests bool
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

	// cache to avoid hitting cas server on every request
	// use the authorization header as key and the authenticationResponse as value
	authorizationHeader := r.Header.Get("Authorization")
	authenticationResponse, keyWasFound := ch.cache.Get(authorizationHeader)
	if !keyWasFound {
		newAuthenticationResponse, err := ch.authenticate(username, password)
		if err != nil {
			if ch.forwardUnauthenticatedRequests {
				if glog.V(1) {
					glog.Infof("cas: rest authentication failed %v", err)
					glog.Infof("unauthenticated request will be forwarded to application")
					ch.h.ServeHTTP(w, r)
					return
				}
			} else {
				// TODO: cache unauthenticated requests
				if glog.V(1) {
					glog.Infof("cas: rest authentication failed %v", err)
				}
				w.Header().Set("WWW-Authenticate", "Basic realm=\"CAS Protected Area\"")
				w.WriteHeader(401)
				return
			}
		}
		ch.cache.Set(authorizationHeader, newAuthenticationResponse, cache.DefaultExpiration)
		setFirstAuthenticatedRequest(r, true)
	}

	authenticationResponse, keyWasFound = ch.cache.Get(authorizationHeader)
	setAuthenticationResponse(r, authenticationResponse.(*AuthenticationResponse))
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
