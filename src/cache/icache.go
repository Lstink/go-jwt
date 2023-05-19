package cache

import "time"

type ICache interface {
	Set(key string, value string, expires time.Duration) error
	Get(key string) (returnValue string, err error)
	Has(key string) bool
	Delete(key string) error
}
