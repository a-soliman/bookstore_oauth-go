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
