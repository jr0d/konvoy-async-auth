package memory

import (
	"fmt"
	"sync"
	"time"

	"github.com/jr0d/konvoy-async-auth/pkg/kaal/server/storage"
)

type MemTokenStorage struct {
	storage map[string]storage.EphemeralToken
	mutex sync.RWMutex
}

func New() MemTokenStorage {
	return MemTokenStorage{
		storage: make(map[string]storage.EphemeralToken),
		mutex:   sync.RWMutex{},
	}
}

func (ts *MemTokenStorage) Create(hmac, rcode string, ttl int64) error {
	et := storage.EphemeralToken{
		RequestCode: rcode,
		TTL: ttl,
		CreatedAt: time.Now().Unix(),
	}
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.storage[hmac] = et
	return nil
}

func (ts *MemTokenStorage) Save(hmac, token string) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	et, ok := ts.storage[hmac]
	if !ok {
		return fmt.Errorf("invalid token storage for hmac: %s\n", hmac)
	}
	et.Token = token
	ts.storage[hmac] = et
	return nil
}

func (ts *MemTokenStorage) Get(hmac string) (storage.EphemeralToken, bool, error) {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	t, ok := ts.storage[hmac]
	return t, ok, nil
}

func (ts *MemTokenStorage) Delete(hmac string) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	delete(ts.storage, hmac)
	return nil
}

func (ts *MemTokenStorage) Prune() {
	now := time.Now().Unix()
	ts.mutex.RLock()
	var expired []string
	for k, v := range ts.storage {
		if v.CreatedAt - now > v.TTL {
			expired = append(expired, k)
		}
	}
	ts.mutex.RUnlock()
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	for _, k := range expired {
		delete(ts.storage, k)
	}
}
