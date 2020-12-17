package traefik_token_middleware

import (
	"context"
	"fmt"
	"strings"
	"net/http"
	"time"
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
)

type Config struct {
	Secret string `json:"secret,omitempty"`
	QueryTokenParam string `json:"queryTokenParam,omitempty"`
	QueryTenantIdParam string `json:"queryTenantIdParam,omitempty"`
	Roles string `json:"roles,omitempty"`
}




func CreateConfig() *Config {
	return &Config{}
}

type JWT struct {
	next		http.Handler
	name		string
	secret		string
	queryTokenParam	string
	queryTenantIdParam	string
	roles string
}

type TokenPayload struct {
	roles      string 
	tenantList string 
	exp        int64  
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if len(config.Secret) == 0 {
		config.Secret = "secret"
	}
	if len(config.QueryTokenParam) == 0 {
		config.QueryTokenParam = "queryTokenParam"
	}
	if len(config.QueryTenantIdParam) == 0 {
		config.QueryTenantIdParam = "queryTenantIdParam"
	}
	if len(config.Roles) == 0 {
		config.Roles = "roles"
	}

	return &JWT{
		next:		next,
		name:		name,
		secret:	config.Secret,
		queryTokenParam: config.QueryTokenParam,
		queryTenantIdParam: config.QueryTenantIdParam,
		roles: config.Roles,
	}, nil
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	queryToken := req.URL.Query().Get(j.queryTokenParam)
	queryTenantId := req.URL.Query().Get(j.queryTenantIdParam)

	if len(j.queryTokenParam) == 0 {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}
	
	token, preprocessError  := preprocessJWT(queryToken)
	if preprocessError != nil {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}
	
	verified, verificationError := verifyJWT(token, j.secret)
	if verificationError != nil {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
		return
	}

	if (verified) {
		// If true decode payload
		payloadJson, decodeErr := decodeBase64(token.payload)
		if decodeErr != nil {
			http.Error(res, "Request error", http.StatusBadRequest)
			return
		}
		var payload TokenPayload;
		json.Unmarshal([]byte(payloadJson), &payload)
		

		if(isExpire(payload.exp)){
			http.Error(res, "Token Expired -> "+string(payload.exp), http.StatusBadRequest)
			return
		} 
		

		if len(j.roles) == 0 {
			if(strings.Contains(j.roles, payload.roles)){
				http.Error(res, "Role Not Permitted", http.StatusBadRequest)
			return
			}
		}

		if len(queryTenantId) == 0 {
			if(strings.Contains(payload.tenantList, queryTenantId)){
				http.Error(res, "Tenant Not Permitted", http.StatusBadRequest)
			return
			}
		}
		
		fmt.Println(payload)
		j.next.ServeHTTP(res, req)
	} else {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
	}
}

// Token Deconstructed header token
type Token struct {
	header string
	payload string
	verification string
}

func isExpire(ctime int64) bool {
	if(ctime < (time.Now().UnixNano() / int64(time.Millisecond) / 1000)){
	return true;
	}
	return false;
}


// verifyJWT Verifies jwt token with secret
func verifyJWT(token Token, secret string) (bool, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	message := token.header + "." + token.payload
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)
	
	decodedVerification, errDecode := base64.RawURLEncoding.DecodeString(token.verification)
	if errDecode != nil {
		return false, errDecode
	}

	if hmac.Equal(decodedVerification, expectedMAC) {
		return true, nil
	}
	return false, nil
	// TODO Add time check to jwt verification
}

// preprocessJWT Takes the request header string, strips prefix and whitespaces and returns a Token
func preprocessJWT(queryToken string) (Token, error) {

	var token Token

	tokenSplit := strings.Split(queryToken, ".")

	if len(tokenSplit) != 3 {
		return token, fmt.Errorf("Invalid token")
	}

	token.header = tokenSplit[0]
	token.payload = tokenSplit[1]
	token.verification = tokenSplit[2]

	return token, nil
}

// decodeBase64 Decode base64 to string
func decodeBase64(baseString string) (string, error) {
	byte, decodeErr := base64.RawURLEncoding.DecodeString(baseString)
	if decodeErr != nil {
		return baseString, fmt.Errorf("Error decoding")
	}
	return string(byte), nil
}


