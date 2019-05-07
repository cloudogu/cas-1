package cas

import (
	"net/http"

	"github.com/golang/glog"
	"github.com/patrickmn/go-cache"
)

// restClientHandler handles CAS REST Protocol over HTTP Basic Authentication
type restClientHandler struct {
	c     RestAuthenticator
	h     http.Handler
	cache *cache.Cache
}

type reaction func(http.ResponseWriter, *http.Request)

// ServeHTTP handles HTTP requests, processes HTTP Basic Authentication over CAS Rest api
// and passes requests up to its child http.Handler.
func (ch *restClientHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if glog.V(2) {
		glog.Infof("cas: handling %v request for %v", r.Method, r.URL)
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		ch.handleUnauthenticatedRequest(w, r)
		return
	}

	// cache to avoid hitting cas server on every request
	// use the authorization header as key and the authenticationResponse as value
	authorizationHeader := r.Header.Get("Authorization")
	_, keyWasFound := ch.cache.Get(authorizationHeader)
	if !keyWasFound {
		reaction := ch.tryToAuthenticateAndCreateReaction(r, username, password)
		ch.cache.Set(authorizationHeader, reaction, cache.DefaultExpiration)
	}

	cachedReaction, keyWasFound := ch.cache.Get(authorizationHeader)
	if f, ok := cachedReaction.(reaction); ok && keyWasFound {
		f(w, r)
	} else {
		if glog.V(1) {
			glog.Error("Unexpected behaviour: did not find a cached reaction for given authorizationHeader")
		}
	}
	return
}

func (ch *restClientHandler) tryToAuthenticateAndCreateReaction(request *http.Request, username string, password string) reaction {
	newAuthenticationResponse, err := ch.authenticate(username, password)
	if err != nil {
		if glog.V(1) {
			glog.Infof("cas: rest authentication failed %v", err)
		}
		// TODO: Check which kind of error (timeout? 401? 50X?) occurred and act appropriately
		return func(writer http.ResponseWriter, req *http.Request) {
			ch.handleUnauthenticatedRequest(writer, req)
		}
	} else {
		setFirstAuthenticatedRequest(request, true)
		return func(writer http.ResponseWriter, req *http.Request) {
			setAuthenticationResponse(req, newAuthenticationResponse)
			ch.h.ServeHTTP(writer, req)
		}
	}
}

func (ch *restClientHandler) handleUnauthenticatedRequest(w http.ResponseWriter, r *http.Request) {
	if ch.c.ShallForwardUnauthenticatedRESTRequests() {
		if glog.V(1) {
			glog.Info("unauthenticated request will be forwarded to application")
		}
		// forward REST request for potential local user authentication or anonymous user
		ch.h.ServeHTTP(w, r)
	} else {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"CAS Protected Area\"")
		w.WriteHeader(401)
	}
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
