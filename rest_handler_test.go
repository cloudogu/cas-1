package cas

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pkg/errors"

	"github.com/patrickmn/go-cache"

	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/assert"
)

type MockedRestClient struct {
	mock.Mock
}

func (m *MockedRestClient) Handle(h http.Handler) http.Handler {
	args := m.Called(h)
	return args.Get(0).(http.Handler)
}

func (m *MockedRestClient) RequestGrantingTicket(username string, password string) (TicketGrantingTicket, error) {
	args := m.Called(username, password)
	return args.Get(0).(TicketGrantingTicket), args.Error(1)
}

func (m *MockedRestClient) RequestServiceTicket(tgt TicketGrantingTicket) (ServiceTicket, error) {
	args := m.Called(tgt)
	return args.Get(0).(ServiceTicket), args.Error(1)
}

func (m *MockedRestClient) ValidateServiceTicket(st ServiceTicket) (*AuthenticationResponse, error) {
	args := m.Called(st)
	return args.Get(0).(*AuthenticationResponse), args.Error(1)
}

func (m *MockedRestClient) Logout(tgt TicketGrantingTicket) error {
	args := m.Called(tgt)
	return args.Error(0)
}

func (m *MockedRestClient) ShallForwardUnauthenticatedRESTRequests() bool {
	args := m.Called()
	return args.Bool(0)
}

type serveCounter struct {
	counter int
}

func (s *serveCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.counter++
}

func TestServeHTTP(t *testing.T) {
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.SetBasicAuth("dirk", "gently")
	m := new(MockedRestClient)
	m.On("RequestGrantingTicket", "dirk", "gently").Return(TicketGrantingTicket("tgt"), nil)
	m.On("RequestServiceTicket", mock.Anything).Return(ServiceTicket("st"), nil)
	m.On("ValidateServiceTicket", mock.Anything).Return(&AuthenticationResponse{}, nil)
	s := &serveCounter{0}
	r := restClientHandler{c: m, h: s, cache: cache.New(time.Minute, time.Minute)}
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, s.counter, 1)
}

func TestServeHTTPCaching(t *testing.T) {
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.SetBasicAuth("dirk", "gently")
	m := new(MockedRestClient)
	m.On("RequestGrantingTicket", "dirk", "gently").Return(TicketGrantingTicket("tgt"), nil)
	m.On("RequestServiceTicket", mock.Anything).Return(ServiceTicket("st"), nil)
	m.On("ValidateServiceTicket", mock.Anything).Return(&AuthenticationResponse{}, nil)
	s := &serveCounter{0}
	r := restClientHandler{c: m, h: s, cache: cache.New(time.Minute, time.Minute)}
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, s.counter, 1)

	// this disables the authentication against cas so we can check if the cache is used
	m.On("RequestGrantingTicket", "dirk", "gently").Return(nil, errors.New("failed"))

	r.ServeHTTP(w, req)
	assert.Equal(t, s.counter, 2)
}

func TestServeHTTPWithWrongCredentialsAndForward(t *testing.T) {
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.SetBasicAuth("dirk", "gently")
	m := new(MockedRestClient)
	m.On("RequestGrantingTicket", "dirk", "gently").Return(TicketGrantingTicket("tgt"),
		errors.New("wrong creds"))
	m.On("ShallForwardUnauthenticatedRESTRequests").Return(true)
	s := &serveCounter{0}
	r := restClientHandler{c: m, h: s, cache: cache.New(time.Minute, time.Minute)}
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, s.counter, 1)
}

func TestServeHTTPWithWrongCredentialsAndForwardCaching(t *testing.T) {
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.SetBasicAuth("dirk", "gently")
	m := new(MockedRestClient)
	m.On("RequestGrantingTicket", "dirk", "gently").Return(TicketGrantingTicket("tgt"),
		errors.New("wrong creds"))
	m.On("ShallForwardUnauthenticatedRESTRequests").Return(true)
	s := &serveCounter{0}
	r := restClientHandler{c: m, h: s, cache: cache.New(time.Minute, time.Minute)}
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, s.counter, 1)

	m.On("RequestGrantingTicket", "dirk", "gently").Return(TicketGrantingTicket("tgt"),
		nil)
	r.ServeHTTP(w, req)
	// without caching the request would now have an authentication response
	assert.Nil(t, getAuthenticationResponse(req))
	assert.Equal(t, s.counter, 2)
}

func TestServeHTTPWithWrongCredentialsAndWithoutForward(t *testing.T) {
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.SetBasicAuth("dirk", "gently")
	m := new(MockedRestClient)
	m.On("RequestGrantingTicket", "dirk", "gently").Return(TicketGrantingTicket("tgt"),
		errors.New("wrong creds"))
	m.On("ShallForwardUnauthenticatedRESTRequests").Return(false)
	s := &serveCounter{0}
	r := restClientHandler{c: m, h: s, cache: cache.New(time.Minute, time.Minute)}
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, s.counter, 0)
	assert.Equal(t, w.Header().Get("WWW-Authenticate"), "Basic realm=\"CAS Protected Area\"")
}

func TestServeHTTPWithoutBasicAuthAndForward(t *testing.T) {
	req, _ := http.NewRequest("GET", "/foo", nil)
	m := new(MockedRestClient)
	m.On("ShallForwardUnauthenticatedRESTRequests").Return(true)
	s := &serveCounter{0}
	r := restClientHandler{c: m, h: s, cache: cache.New(time.Minute, time.Minute)}
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, s.counter, 1)
}

func TestServeHTTPWithoutBasicAuthAndWithoutForward(t *testing.T) {
	req, _ := http.NewRequest("GET", "/foo", nil)
	m := new(MockedRestClient)
	m.On("ShallForwardUnauthenticatedRESTRequests").Return(false)
	s := &serveCounter{0}
	r := restClientHandler{c: m, h: s, cache: cache.New(time.Minute, time.Minute)}
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, s.counter, 0)
	assert.Equal(t, w.Header().Get("WWW-Authenticate"), "Basic realm=\"CAS Protected Area\"")
}
