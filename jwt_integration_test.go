// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2016 LabStack and Echo contributors

package echojwt_test

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIntegrationMiddlewareWithHandler(t *testing.T) {
	e := echo.New()
	e.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: []byte("secret"),
	}))

	e.GET("/example", exampleHandler)

	req := httptest.NewRequest(http.MethodGet, "/example", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
	res := httptest.NewRecorder()

	e.ServeHTTP(res, req)

	if res.Code != 200 {
		t.Failed()
	}
}

func exampleHandler(c echo.Context) error {
	// make sure that your imports are correct versions. for example if you use `"github.com/golang-jwt/jwt"` as
	// import this cast will fail and `"github.com/golang-jwt/jwt/v5"` will succeed.
	// Although `.(*jwt.Token)` looks exactly the same for both packages but this struct is still different
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return errors.New("JWT token missing or invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims) // by default claims is of type `jwt.MapClaims`
	if !ok {
		return errors.New("failed to cast claims as jwt.MapClaims")
	}
	return c.JSON(http.StatusOK, claims)
}
