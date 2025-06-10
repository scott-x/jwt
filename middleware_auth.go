package jwt4

import (
	"context"
	"strconv"
	"strings"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/go-kratos/kratos/v2/transport/http"
)

// Define a private type to use as a context key to avoid conflicts.
type contextKey string

const (
	authorizationKey = "Authorization"
	bearerWord       = "Bearer"
	// Change uid to private context key
	contextUserIDKey contextKey = "user_id"
)

func Auth(jwtSecret string, whiteList []string) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if tr, ok := transport.FromServerContext(ctx); ok {
				if ht, ok := tr.(*http.Transport); ok {
					// check if the endpoint is in whiteList
					for _, path := range whiteList {
						if ht.Request().URL.Path == path {
							return handler(ctx, req)
						}
					}
					authHeader := ht.Request().Header.Get(authorizationKey)
					if authHeader == "" {
						return nil, errors.Unauthorized("UNAUTHORIZED", "Authorization header is missing")
					}

					token := strings.TrimPrefix(authHeader, bearerWord+" ")
					claims, err := parseToken(jwtSecret, token)
					if err != nil {
						return nil, errors.Unauthorized("UNAUTHORIZED", err.Error())
					}

					// save user_id to context
					ctx = context.WithValue(ctx, contextUserIDKey, claims.UserID)
				}
			}
			return handler(ctx, req)
		}
	}
}


// GetUid:  get user_id from context
// Return an error if the user_id does not exist or its type is mismatched
func GetUid(ctx context.Context) (int, error) {
	val := ctx.Value(contextUserIDKey) // Access the value via the private userContextKey

	if val == nil {
		// user_id is absent from the context. This may be due to unexecuted middleware or a failed authentication.
		return 0, errors.Unauthorized("UNAUTHORIZED", "user_id not found in context")
	}

	// Try to assert the value as an int type
	// If claims.UserID is a string type, you'll need to convert int here
	if uid, ok := val.(int); ok {
		return uid, nil
	}

	// If the user_id is a string type, convert it
	if uidStr, ok := val.(string); ok {
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			return 0, errors.InternalServer("INTERNAL_ERROR", "invalid user_id format in context")
		}
		return uid, nil
	}

	// If the type doesn't match int or string
	return 0, errors.InternalServer("INTERNAL_ERROR", "user_id in context is not of expected type")
}