package oauth

import (
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/federicoleon/golang-restclient/rest"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	rest.StartMockupServer()

	os.Exit(m.Run())
}

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientID)
	assert.EqualValues(t, "X-Caller-Id", headerXCallerID)
	assert.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsPublicNilRequest(t *testing.T) {
	isPublic := IsPublic(nil)
	assert.True(t, isPublic)
}
func TestIsPublicTrue(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	req.Header.Add(headerXPublic, "true")
	isPublic := IsPublic(req)

	assert.True(t, isPublic)
}

func TestIsPublicFalse(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	isPublic := IsPublic(req)

	assert.False(t, isPublic)
}

func TestGetClientIDNilReq(t *testing.T) {
	clientID := GetClientID(nil)

	assert.EqualValues(t, 0, clientID)
}

func TestGetClientIDInvalidID(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	req.Header.Add(headerXClientID, "not an integer")

	clientID := GetClientID(req)

	assert.EqualValues(t, 0, clientID)
}

func TestGetClientIDValid(t *testing.T) {
	clientIDToSet := 1

	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	req.Header.Add(headerXClientID, strconv.Itoa(clientIDToSet))

	clientID := GetClientID(req)

	assert.EqualValues(t, clientIDToSet, clientID)
}

func TestGetCallerIDNilReq(t *testing.T) {
	callerID := GetCallerID(nil)

	assert.EqualValues(t, 0, callerID)
}

func TestGetCallerIDInvalid(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	req.Header.Add(headerXCallerID, "not an integer")

	callerID := GetCallerID(nil)

	assert.EqualValues(t, 0, callerID)
}

func TestGetCallerIDValid(t *testing.T) {
	callerIDToTest := 1

	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	req.Header.Add(headerXCallerID, strconv.Itoa(callerIDToTest))

	callerID := GetCallerID(req)

	assert.EqualValues(t, callerIDToTest, callerID)
}

func TestGetAccessTokenInvalidRestclientResponse(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/Abc123",
		ReqBody:      ``,
		RespHTTPCode: -1,
		RespBody:     `{}`,
	})

	accessToken, err := getAccessToken("Abc123")

	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, "invalid restclient response while trying to get access token", err.Message())
	assert.EqualValues(t, http.StatusInternalServerError, err.Status())
}

func TestGetAccessTokenInvalidErrorInterface(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/Abc123",
		ReqBody:      ``,
		RespHTTPCode: 404,
		RespBody:     `{"message": "error returned", "status": "404", "error": "test_error", "causes": ["some"]}`,
	})

	accessToken, err := getAccessToken("Abc123")

	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, "invalid error interface when trying to get access token", err.Message())
	assert.EqualValues(t, 500, err.Status())
}

func TestGetAccessTokenErrorReturned(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/Abc123",
		ReqBody:      ``,
		RespHTTPCode: 404,
		RespBody:     `{"message": "error returned", "status": 404, "error": "test_error", "causes": ["some"]}`,
	})

	accessToken, err := getAccessToken("Abc123")

	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, "error returned", err.Message())
	assert.EqualValues(t, 404, err.Status())
}

func TestGetAccessTokenBadAccessTokenJSON(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/Abc123",
		ReqBody:      ``,
		RespHTTPCode: 200,
		RespBody:     `{"id": "someAccesstokenID", "user_id": "1", "client_id": 1}`,
	})

	accessToken, err := getAccessToken("Abc123")

	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, "error while trying to unmarshal users response to get access token", err.Message())
	assert.EqualValues(t, 500, err.Status())
}

func TestGetAccessTokenNoError(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/Abc123",
		ReqBody:      ``,
		RespHTTPCode: 200,
		RespBody:     `{"id": "someAccesstokenID", "user_id": 1, "client_id": 1}`,
	})

	accessToken, err := getAccessToken("Abc123")

	assert.Nil(t, err)
	assert.NotNil(t, accessToken)
	assert.EqualValues(t, "someAccesstokenID", accessToken.ID)
	assert.EqualValues(t, 1, accessToken.UserID)
	assert.EqualValues(t, 1, accessToken.ClientID)
}

func TestAuthenticateRequestNilReq(t *testing.T) {
	err := AuthenticateRequest(nil)
	assert.Nil(t, err)
}

func TestAuthenticateRequestNoAccessTokenParam(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	err := AuthenticateRequest(req)
	assert.Nil(t, err)
}

func TestAuthenticateRequestNotFound(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/Abc123",
		ReqBody:      ``,
		RespHTTPCode: 404,
		RespBody:     `{"message": "not found", "status": 404, "error": "not_found"}`,
	})

	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	q := req.URL.Query()
	q.Add(paramAccessToken, "Abc123")
	req.URL.RawQuery = q.Encode()
	err := AuthenticateRequest(req)
	assert.Nil(t, err)
}

func TestAuthenticateRequestError(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/Abc123",
		ReqBody:      ``,
		RespHTTPCode: -1,
		RespBody:     `{}`,
	})

	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	q := req.URL.Query()
	q.Add(paramAccessToken, "Abc123")
	req.URL.RawQuery = q.Encode()
	err := AuthenticateRequest(req)
	assert.NotNil(t, err)
}

func TestAuthenticateRequestNoError(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/Abc123",
		ReqBody:      ``,
		RespHTTPCode: 200,
		RespBody:     `{"id": "someAccesstokenID", "user_id": 1, "client_id": 1}`,
	})

	req, _ := http.NewRequest(http.MethodGet, "/testing", nil)
	q := req.URL.Query()
	q.Add(paramAccessToken, "Abc123")
	req.URL.RawQuery = q.Encode()
	err := AuthenticateRequest(req)
	assert.Nil(t, err)
}
