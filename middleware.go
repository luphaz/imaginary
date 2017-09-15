package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"crypto/md5"
	"encoding/hex"
	"net/url"

	"github.com/daaku/go.httpgzip"
	"github.com/rs/cors"
	"gopkg.in/h2non/bimg.v1"
	"gopkg.in/throttled/throttled.v2"
	"gopkg.in/throttled/throttled.v2/store/memstore"
)

func Middleware(fn func(http.ResponseWriter, *http.Request), o ServerOptions) http.Handler {
	next := http.Handler(http.HandlerFunc(fn))

	if o.SecretToken != "" {
		next = validateToken(next, o)
	}
	if o.Concurrency > 0 {
		next = throttle(next, o)
	}
	if o.Gzip {
		next = httpgzip.NewHandler(next)
	}
	if o.CORS {
		next = cors.Default().Handler(next)
	}
	if o.ApiKey != "" {
		next = authorizeClient(next, o)
	}
	if o.HttpCacheTtl >= 0 {
		next = setCacheHeaders(next, o.HttpCacheTtl)
	}

	return validate(defaultHeaders(next), o)
}

func ImageMiddleware(o ServerOptions) func(Operation) http.Handler {
	return func(fn Operation) http.Handler {
		return validateImage(Middleware(imageController(o, Operation(fn)), o), o)
	}
}

func throttleError(err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "throttle error: "+err.Error(), http.StatusInternalServerError)
	})
}

func throttle(next http.Handler, o ServerOptions) http.Handler {
	store, err := memstore.New(65536)
	if err != nil {
		return throttleError(err)
	}

	quota := throttled.RateQuota{throttled.PerSec(o.Concurrency), o.Burst}
	rateLimiter, err := throttled.NewGCRARateLimiter(store, quota)
	if err != nil {
		return throttleError(err)
	}

	httpRateLimiter := throttled.HTTPRateLimiter{
		RateLimiter: rateLimiter,
		VaryBy:      &throttled.VaryBy{Method: true},
	}

	return httpRateLimiter.RateLimit(next)
}

func validate(next http.Handler, o ServerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "POST" {
			ErrorReply(r, w, ErrMethodNotAllowed, o)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func validateImage(next http.Handler, o ServerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if r.Method == "GET" && isPublicPath(path) {
			next.ServeHTTP(w, r)
			return
		}

		if r.Method == "GET" && o.Mount == "" && o.EnableURLSource == false {
			ErrorReply(r, w, ErrMethodNotAllowed, o)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type KeyValue struct {
	Key string
	Value string
}

func ParseQuery(query string) ([]KeyValue, error) {
	var keyValueArray []KeyValue
	err := parseQuery(&keyValueArray, query)
	return keyValueArray, err
}

func parseQuery(keyValueArray *[]KeyValue, query string) (err error) {
	for query != "" {
		key := query
		if i := strings.IndexAny(key, "&;"); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.Index(key, "="); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key, err1 := url.QueryUnescape(key)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		value, err1 = url.QueryUnescape(value)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		*keyValueArray = append(*keyValueArray, KeyValue{Key: key, Value: value})
	}
	return err
}

func validateToken(next http.Handler, o ServerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if r.Method == "GET" && isPublicPath(path) {
			next.ServeHTTP(w, r)
			return
		}

		if r.Method == "GET" {
			// a custom query parser is used in order to retain
			// the query parameter order
			keyValueArray, _ := ParseQuery(r.URL.RawQuery)
			var paramsArray []string
			token := ""
			for _, kv := range keyValueArray {
				if(kv.Key == "token") {
					token = kv.Value
				} else {
					paramsArray = append(paramsArray, kv.Key + "=" + kv.Value)
				}
			}
			urlWithoutToken := r.URL.Path + "?" + strings.Join(paramsArray, "&")
			if token == "" {
				ErrorReply(r, w, ErrSecureTokenMissing, o)
				return
			}
			hasher := md5.New()
			hasher.Write([]byte(o.SecretToken + urlWithoutToken))
			expectedToken := hex.EncodeToString(hasher.Sum(nil))
			if(token != expectedToken) {
				ErrorReply(r, w, ErrSecureToken, o)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func authorizeClient(next http.Handler, o ServerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("API-Key")
		if key == "" {
			key = r.URL.Query().Get("key")
		}

		if key != o.ApiKey {
			ErrorReply(r, w, ErrInvalidApiKey, o)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func defaultHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", fmt.Sprintf("imaginary %s (bimg %s)", Version, bimg.Version))
		next.ServeHTTP(w, r)
	})
}

func setCacheHeaders(next http.Handler, ttl int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer next.ServeHTTP(w, r)

		if r.Method != "GET" || isPublicPath(r.URL.Path) {
			return
		}

		ttlDiff := time.Duration(ttl) * time.Second
		expires := time.Now().Add(ttlDiff)

		w.Header().Add("Expires", strings.Replace(expires.Format(time.RFC1123), "UTC", "GMT", -1))
		w.Header().Add("Cache-Control", getCacheControl(ttl))
	})
}

func getCacheControl(ttl int) string {
	if ttl == 0 {
		return "private, no-cache, no-store, must-revalidate"
	}
	return fmt.Sprintf("public, s-maxage=%d, max-age=%d, no-transform", ttl, ttl)
}

func isPublicPath(path string) bool {
	return path == "/" || path == "/health" || path == "/form"
}
