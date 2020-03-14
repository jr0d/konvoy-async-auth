package kaal

const (
	InitEndpoint     = "/async"
	AuthEndpoint     = "/async/auth"
	CallbackEndpoint = "/async/auth/callback"
	QueryEndpoint    = "/async/query"
)

type InitAsyncOIDCRequest struct {
	// RequestCode is passed to the async auth service and stored by the server. The server will use
	// this code to authenticate client requests for token retrieval
	RequestCode	string `json:"requestCode"`
}

type InitAsyncOIDCResponse struct {
	AuthURL 	  string	`json:"authURL"`
	Hmac      	  string    `json:"hmac"`
	HmacTTL       int64     `json:"ttl"`
}

type QueryAsyncOIDCResponse struct {
	Token string `json:"token"`
	Ready bool   `json:"ready"`
}
