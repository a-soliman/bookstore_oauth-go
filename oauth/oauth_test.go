package oauth

import (
	"net/http"
	"os"
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
