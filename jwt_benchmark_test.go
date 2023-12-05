package echojwt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	echo "github.com/datumforge/echox"
)

func BenchmarkJWTSuccessPath(b *testing.B) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		token := c.Get("user").(*jwt.Token)
		return c.JSON(http.StatusTeapot, token.Claims)
	})

	b.ReportAllocs()
	mw, err := Config{SigningKey: []byte("secret")}.ToMiddleware()
	if err != nil {
		b.Fatal(err)
	}
	e.Use(mw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
		res := httptest.NewRecorder()

		e.ServeHTTP(res, req)

		if res.Code != http.StatusUnauthorized {
			b.Failed()
		}
	}
}

func BenchmarkJWTErrorPath(b *testing.B) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		token := c.Get("user").(*jwt.Token)
		return c.JSON(http.StatusTeapot, token.Claims)
	})

	b.ReportAllocs()
	mw, err := Config{SigningKey: []byte("secret")}.ToMiddleware()
	if err != nil {
		b.Fatal(err)
	}
	e.Use(mw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer x.x.x")
		res := httptest.NewRecorder()

		e.ServeHTTP(res, req)

		if res.Code != http.StatusUnauthorized {
			b.Failed()
		}
	}
}
