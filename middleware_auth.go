package jwt4

import (
	"context"
	"strings"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/go-kratos/kratos/v2/transport/http"
)

const (
	authorizationKey = "Authorization"
	bearerWord       = "Bearer"
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
					ctx = context.WithValue(ctx, "user_id", claims.UserID)
				}
			}
			return handler(ctx, req)
		}
	}
}
