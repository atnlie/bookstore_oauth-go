package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access-token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}

	return req.Header.Get(headerXPublic) == "true"
}

func GetCallerId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(req.Header.Get(headerXCallerId), 10, 0)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(req.Header.Get(headerXClientId), 10, 0)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticationRequest(req *http.Request) *utils.RestErr {
	if req == nil {
		return RestError
	}

	cleanRequest(req)

	atId := strings.TrimSpace(req.URL.Query().Get(paramAccessToken))
	if atId == "" {
		return nil
	}

	at, err := GetAccessToken(atId)
	if err != nil {
		return err
	}

	req.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	req.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(req *http.Request)  {
	if req == nil {
		return
	}
	req.Header.Del(headerXClientId)
	req.Header.Del(headerXCallerId)
}

func GetAccessToken(aTokenId string) (*accessToken, *utils.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", aTokenId))
	if response == nil || response.Response == nil {
		return nil, utils.CustomInternalServerError("invalid rest-client response when trying login")
	}

	if response.StatusCode > 299 {
		var restErr utils.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, utils.CustomInternalServerError("invalid interface error when trying to login user")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, utils.CustomInternalServerError("error when trying unmarshal users response")
	}

	return &at, nil
}
