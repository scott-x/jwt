# jwt4

```bash
go get github.com/scott-x/jwt/v4@4.0.2
```

### api

- `func GenerateJWTToken(secret string, expires time.Duration, userID int64) (string, error)`: Generate JWT token if login successfuly
- `func Auth(jwtSecret string, whiteList []string) middleware.Middleware`: jwt middleware
- `func GetUid(ctx context.Context) (int, error)`: get user id