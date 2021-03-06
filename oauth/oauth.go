package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/a-soliman/bookstore_utils-go/rest_errors"
	"github.com/federicoleon/golang-restclient/rest"
	"github.com/joho/godotenv"
)

const (
	oauthServiceURL = "OAUTH_MICROSERVICE_URL"
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	baseURL         = goDotEnvVariable(oauthServiceURL)
	oauthRestClient = rest.RequestBuilder{
		BaseURL: baseURL,
		Timeout: 2 * time.Second,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

type oauthInterface interface{}

// IsPublic returns true if the request is public
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

// GetClientID returns the clientID from the request header or 0 if an error occurred
func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	ClientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return ClientID
}

// GetCallerID returns the callerID from the request header or 0 if an error occurred
func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

// AuthenticateRequest authenticates a given request, after clearing it from X headers, then appending clientId and the callerId headers
func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenID := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenID == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenID)
	if err != nil {
		if err.Status() == http.StatusNotFound { // the 404 should not be treated as an authentication error
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, rest_errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenID))
	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError("invalid restclient response while trying to get access token", errors.New("network timeout"))
	}

	if response.StatusCode > 299 {
		restErr, err := rest_errors.NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", err)
		}
		return nil, restErr
	}

	var at accessToken

	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error while trying to unmarshal users response to get access token", errors.New("error processing json"))
	}
	return &at, nil
}

func goDotEnvVariable(key string) string {

	// load .env file
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	return os.Getenv(key)
}
