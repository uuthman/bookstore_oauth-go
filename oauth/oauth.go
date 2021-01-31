package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/federicoleon/go-httpclient/gohttp"
	"github.com/uuthman/bookstore_oauth-go/oauth/errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID   = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = gohttp.NewBuilder().SetConnectionTimeout(200 * time.Millisecond).Build()
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

func isPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64{

	if request == nil{
		return 0
	}

	callerId,err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(request *http.Request) int64{

	if request == nil{
		return 0
	}

	clientId,err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	
	if err != nil {
		return 0
	}

	return clientId
}





func AuthenticateRequest(request *http.Request) *errors.RestErr {

	if request == nil {
		return nil
	}

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))

	if accessTokenId == "" {
		return nil
	}

	cleanRequest(request)

	at,err := getAccessToken(accessTokenId)
	
	if err != nil {
		return err
	}

	request.Header.Add(headerXClientID,fmt.Sprintf("%v",at.UserID))
	request.Header.Add(headerXCallerID,fmt.Sprintf("%v",at.ClientID))

	return nil
}

func cleanRequest(request *http.Request){
	if request == nil {
		return
	}

	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)	

}

func getAccessToken(accessTokenId string) (*accessToken,*errors.RestErr){

	response,err := oauthRestClient.Get(fmt.Sprintf("http://localhost:8080/oauth/access_token/%s",accessTokenId))

	if err != nil {
		return nil, errors.NewInternalServerError("invalid restclient response when trying to login user")
	}


	if response.StatusCode() > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to login user")
		}
		return nil, &restErr
	}

	var user accessToken
	if err := json.Unmarshal(response.Bytes(), &user); err != nil {
		return nil, errors.NewInternalServerError("error interface when trying to unmarshal users response")
	}

	return &user, nil
}
