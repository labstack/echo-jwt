// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2016 LabStack and Echo contributors

package echojwt_test

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v5"
	"github.com/labstack/echo/v5"
)

func ExampleWithConfig_usage() {
	e := echo.New()

	e.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: []byte("secret"),
	}))

	e.GET("/", func(c *echo.Context) error {
		// make sure that your imports are correct versions. for example if you use `"github.com/golang-jwt/jwt"` as
		// import this cast will fail and `"github.com/golang-jwt/jwt/v5"` will succeed.
		// Although `.(*jwt.Token)` looks exactly the same for both packages but this struct is still different
		token, ok := c.Get("user").(*jwt.Token) // by default token is stored under `user` key
		if !ok {
			return errors.New("JWT token missing or invalid")
		}
		claims, ok := token.Claims.(jwt.MapClaims) // by default claims is of type `jwt.MapClaims`
		if !ok {
			return errors.New("failed to cast claims as jwt.MapClaims")
		}
		return c.JSON(http.StatusOK, claims)
	})

	// ----------------------- start server on random port -----------------------
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	go func(e *echo.Echo, l net.Listener) {
		s := http.Server{Handler: e}
		if err := s.Serve(l); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}(e, l)
	time.Sleep(100 * time.Millisecond)

	// ----------------------- execute HTTP request with valid token and check the response -----------------------
	requestURL := fmt.Sprintf("http://%v", l.Addr().String())
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set(echo.HeaderAuthorization, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Response: status code: %d, body: %s\n", res.StatusCode, body)

	// Output: Response: status code: 200, body: {"admin":true,"name":"John Doe","sub":"1234567890"}
}
