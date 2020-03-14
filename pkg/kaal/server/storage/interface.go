package storage

type TokenStore interface {
	Create(hmac, rcode string, ttl int64) error
	Save(hmac, idToken string) error
	Get(hmac string) (EphemeralToken, bool, error)
	Delete(hmac string) error
	Prune()
}

type EphemeralToken struct {
	Token string
	RequestCode string
	TTL int64
	CreatedAt int64
}
