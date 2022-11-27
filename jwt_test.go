// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2016 LabStack and Echo contributors

package echojwt

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
)

// jwtCustomInfo defines some custom types we're going to use within our tokens.
type jwtCustomInfo struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

// jwtCustomClaims are custom claims expanding default ones.
type jwtCustomClaims struct {
	jwt.RegisteredClaims
	jwtCustomInfo
}

func TestJWT(t *testing.T) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		token := c.Get("user").(*jwt.Token)
		return c.JSON(http.StatusOK, token.Claims)
	})

	e.Use(JWT([]byte("secret")))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
	res := httptest.NewRecorder()

	e.ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, `{"admin":true,"name":"John Doe","sub":"1234567890"}`+"\n", res.Body.String())
}

func TestJWT_combinations(t *testing.T) {
	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	}
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	validKey := []byte("secret")
	invalidKey := []byte("invalid-key")
	validAuth := "Bearer " + token

	var testCases = []struct {
		name                    string
		config                  Config
		reqURL                  string // "/" if empty
		hdrAuth                 string
		hdrCookie               string // test.Request doesn't provide SetCookie(); use name=val
		formValues              map[string]string
		expectPanic             bool
		expectToMiddlewareError string
		expectError             string
	}{
		{
			name:                    "No signing key provided",
			expectToMiddlewareError: "jwt middleware requires signing key",
		},
		{
			name: "invalid TokenLookup",
			config: Config{
				SigningKey:    validKey,
				SigningMethod: "RS256",
				TokenLookup:   "q",
			},
			expectToMiddlewareError: "extractor source for lookup could not be split into needed parts: q",
		},
		{
			name:    "Unexpected signing method",
			hdrAuth: validAuth,
			config: Config{
				SigningKey:    validKey,
				SigningMethod: "RS256",
			},
			expectError: "code=401, message=invalid or expired jwt, internal=unexpected jwt signing method=HS256",
		},
		{
			name:    "Invalid key",
			hdrAuth: validAuth,
			config: Config{
				SigningKey: invalidKey,
			},
			expectError: "code=401, message=invalid or expired jwt, internal=signature is invalid",
		},
		{
			name:    "Valid JWT",
			hdrAuth: validAuth,
			config: Config{
				SigningKey: validKey,
			},
		},
		{
			name:    "Valid JWT with custom AuthScheme",
			hdrAuth: "Token" + " " + token,
			config: Config{
				TokenLookup: "header:" + echo.HeaderAuthorization + ":Token ",
				SigningKey:  validKey,
			},
		},
		{
			name:    "Valid JWT with custom claims",
			hdrAuth: validAuth,
			config: Config{
				SigningKey: []byte("secret"),
				NewClaimsFunc: func(c echo.Context) jwt.Claims {
					return &jwtCustomClaims{ // this needs to be pointer to json unmarshalling to work
						jwtCustomInfo: jwtCustomInfo{
							Name:  "John Doe",
							Admin: true,
						},
					}
				},
			},
		},
		{
			name:    "Invalid Authorization header",
			hdrAuth: "invalid-auth",
			config: Config{
				SigningKey: validKey,
			},
			expectError: "code=401, message=missing or malformed jwt, internal=invalid value in request header",
		},
		{
			name: "Empty header auth field",
			config: Config{
				SigningKey: validKey,
			},
			expectError: "code=401, message=missing or malformed jwt, internal=invalid value in request header",
		},
		{
			name: "Valid query method",
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "query:jwt",
			},
			reqURL: "/?a=b&jwt=" + token,
		},
		{
			name: "Invalid query param name",
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "query:jwt",
			},
			reqURL:      "/?a=b&jwtxyz=" + token,
			expectError: "code=401, message=missing or malformed jwt, internal=missing value in the query string",
		},
		{
			name: "Invalid query param value",
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "query:jwt",
			},
			reqURL:      "/?a=b&jwt=invalid-token",
			expectError: "code=401, message=invalid or expired jwt, internal=token contains an invalid number of segments",
		},
		{
			name: "Empty query",
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "query:jwt",
			},
			reqURL:      "/?a=b",
			expectError: "code=401, message=missing or malformed jwt, internal=missing value in the query string",
		},
		{
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "param:jwt",
			},
			reqURL: "/" + token,
			name:   "Valid param method",
		},
		{
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "cookie:jwt",
			},
			hdrCookie: "jwt=" + token,
			name:      "Valid cookie method",
		},
		{
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "query:jwt,cookie:jwt",
			},
			hdrCookie: "jwt=" + token,
			name:      "Multiple jwt lookuop",
		},
		{
			name: "Invalid token with cookie method",
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "cookie:jwt",
			},
			hdrCookie:   "jwt=invalid",
			expectError: "code=401, message=invalid or expired jwt, internal=token contains an invalid number of segments",
		},
		{
			name: "Empty cookie",
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "cookie:jwt",
			},
			expectError: "code=401, message=missing or malformed jwt, internal=missing value in cookies",
		},
		{
			name: "Valid form method",
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "form:jwt",
			},
			formValues: map[string]string{"jwt": token},
		},
		{
			name: "Invalid token with form method",
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "form:jwt",
			},
			formValues:  map[string]string{"jwt": "invalid"},
			expectError: "code=401, message=invalid or expired jwt, internal=token contains an invalid number of segments",
		},
		{
			name: "Empty form field",
			config: Config{
				SigningKey:  validKey,
				TokenLookup: "form:jwt",
			},
			expectError: "code=401, message=missing or malformed jwt, internal=missing value in the form",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.reqURL == "" {
				tc.reqURL = "/"
			}

			var req *http.Request
			if len(tc.formValues) > 0 {
				form := url.Values{}
				for k, v := range tc.formValues {
					form.Set(k, v)
				}
				req = httptest.NewRequest(http.MethodPost, tc.reqURL, strings.NewReader(form.Encode()))
				req.Header.Set(echo.HeaderContentType, "application/x-www-form-urlencoded")
				req.ParseForm()
			} else {
				req = httptest.NewRequest(http.MethodGet, tc.reqURL, nil)
			}
			res := httptest.NewRecorder()
			req.Header.Set(echo.HeaderAuthorization, tc.hdrAuth)
			req.Header.Set(echo.HeaderCookie, tc.hdrCookie)
			c := e.NewContext(req, res)

			if tc.reqURL == "/"+token {
				c.SetParamNames("jwt")
				c.SetParamValues(token)
			}

			mw, err := tc.config.ToMiddleware()
			if tc.expectToMiddlewareError != "" {
				assert.EqualError(t, err, tc.expectToMiddlewareError)
				return
			}

			hErr := mw(handler)(c)
			if tc.expectError != "" {
				assert.EqualError(t, hErr, tc.expectError)
				return
			}
			if !assert.NoError(t, hErr) {
				return
			}

			user := c.Get("user").(*jwt.Token)
			switch claims := user.Claims.(type) {
			case jwt.MapClaims:
				assert.Equal(t, claims["name"], "John Doe")
			case *jwtCustomClaims:
				assert.Equal(t, claims.Name, "John Doe")
				assert.Equal(t, claims.Admin, true)
			default:
				panic("unexpected type of claims")
			}
		})
	}
}

func TestJWTwithKID(t *testing.T) {
	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	}
	firstToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImZpcnN0T25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.w5VGpHOe0jlNgf7jMVLHzIYH_XULmpUlreJnilwSkWk"
	secondToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InNlY29uZE9uZSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.sdghDYQ85jdh0hgQ6bKbMguLI_NSPYWjkhVJkee-yZM"
	wrongToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InNlY29uZE9uZSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.RyhLybtVLpoewF6nz9YN79oXo32kAtgUxp8FNwTkb90"
	staticToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.1_-XFYUPpJfgsaGwYhgZEt7hfySMg-a3GN-nfZmbW7o"
	validKeys := map[string]interface{}{"firstOne": []byte("first_secret"), "secondOne": []byte("second_secret")}
	invalidKeys := map[string]interface{}{"thirdOne": []byte("third_secret")}
	staticSecret := []byte("static_secret")
	invalidStaticSecret := []byte("invalid_secret")

	for _, tc := range []struct {
		expErrCode int // 0 for Success
		config     Config
		hdrAuth    string
		info       string
	}{
		{
			hdrAuth: "Bearer " + firstToken,
			config:  Config{SigningKeys: validKeys},
			info:    "First token valid",
		},
		{
			hdrAuth: "Bearer " + secondToken,
			config:  Config{SigningKeys: validKeys},
			info:    "Second token valid",
		},
		{
			expErrCode: http.StatusUnauthorized,
			hdrAuth:    "Bearer " + wrongToken,
			config:     Config{SigningKeys: validKeys},
			info:       "Wrong key id token",
		},
		{
			hdrAuth: "Bearer " + staticToken,
			config:  Config{SigningKey: staticSecret},
			info:    "Valid static secret token",
		},
		{
			expErrCode: http.StatusUnauthorized,
			hdrAuth:    "Bearer " + staticToken,
			config:     Config{SigningKey: invalidStaticSecret},
			info:       "Invalid static secret",
		},
		{
			expErrCode: http.StatusUnauthorized,
			hdrAuth:    "Bearer " + firstToken,
			config:     Config{SigningKeys: invalidKeys},
			info:       "Invalid keys first token",
		},
		{
			expErrCode: http.StatusUnauthorized,
			hdrAuth:    "Bearer " + secondToken,
			config:     Config{SigningKeys: invalidKeys},
			info:       "Invalid keys second token",
		},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()
		req.Header.Set(echo.HeaderAuthorization, tc.hdrAuth)
		c := e.NewContext(req, res)

		if tc.expErrCode != 0 {
			h := WithConfig(tc.config)(handler)
			he := h(c).(*echo.HTTPError)
			assert.Equal(t, tc.expErrCode, he.Code, tc.info)
			continue
		}

		h := WithConfig(tc.config)(handler)
		if assert.NoError(t, h(c), tc.info) {
			user := c.Get("user").(*jwt.Token)
			switch claims := user.Claims.(type) {
			case jwt.MapClaims:
				assert.Equal(t, claims["name"], "John Doe", tc.info)
			case *jwtCustomClaims:
				assert.Equal(t, claims.Name, "John Doe", tc.info)
				assert.Equal(t, claims.Admin, true, tc.info)
			default:
				panic("unexpected type of claims")
			}
		}
	}
}

func TestConfig_skipper(t *testing.T) {
	e := echo.New()

	e.Use(WithConfig(Config{
		Skipper: func(context echo.Context) bool {
			return true // skip everything
		},
		SigningKey: []byte("secret"),
	}))

	isCalled := false
	e.GET("/", func(c echo.Context) error {
		isCalled = true
		return c.String(http.StatusTeapot, "test")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	e.ServeHTTP(res, req)

	assert.Equal(t, http.StatusTeapot, res.Code)
	assert.True(t, isCalled)
}

func TestConfig_BeforeFunc(t *testing.T) {
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusTeapot, "test")
	})

	isCalled := false
	e.Use(WithConfig(Config{
		BeforeFunc: func(context echo.Context) {
			isCalled = true
		},
		SigningKey: []byte("secret"),
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
	res := httptest.NewRecorder()
	e.ServeHTTP(res, req)

	assert.Equal(t, http.StatusTeapot, res.Code)
	assert.True(t, isCalled)
}

func TestConfig_extractorErrorHandling(t *testing.T) {
	var testCases = []struct {
		name             string
		given            Config
		expectStatusCode int
	}{
		{
			name: "ok, ErrorHandler is executed",
			given: Config{
				SigningKey: []byte("secret"),
				ErrorHandler: func(c echo.Context, err error) error {
					return echo.NewHTTPError(http.StatusTeapot, "custom_error")
				},
			},
			expectStatusCode: http.StatusTeapot,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			e.GET("/", func(c echo.Context) error {
				return c.String(http.StatusNotImplemented, "should not end up here")
			})

			e.Use(WithConfig(tc.given))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			res := httptest.NewRecorder()
			e.ServeHTTP(res, req)

			assert.Equal(t, tc.expectStatusCode, res.Code)
		})
	}
}

func TestConfig_parseTokenErrorHandling(t *testing.T) {
	var testCases = []struct {
		name      string
		given     Config
		expectErr string
	}{
		{
			name: "ok, ErrorHandler is executed",
			given: Config{
				ErrorHandler: func(c echo.Context, err error) error {
					return echo.NewHTTPError(http.StatusTeapot, "ErrorHandler: "+err.Error())
				},
			},
			expectErr: "{\"message\":\"ErrorHandler: parsing failed\"}\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			//e.Debug = true
			e.GET("/", func(c echo.Context) error {
				return c.String(http.StatusNotImplemented, "should not end up here")
			})

			config := tc.given
			parseTokenCalled := false
			config.ParseTokenFunc = func(c echo.Context, auth string) (interface{}, error) {
				parseTokenCalled = true
				return nil, errors.New("parsing failed")
			}
			e.Use(WithConfig(config))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(echo.HeaderAuthorization, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
			res := httptest.NewRecorder()

			e.ServeHTTP(res, req)

			assert.Equal(t, http.StatusTeapot, res.Code)
			assert.Equal(t, tc.expectErr, res.Body.String())
			assert.True(t, parseTokenCalled)
		})
	}
}

func TestConfig_custom_ParseTokenFunc_Keyfunc(t *testing.T) {
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusTeapot, "test")
	})

	// example of minimal custom ParseTokenFunc implementation. Allows you to use different versions of `github.com/golang-jwt/jwt`
	// with current JWT middleware
	signingKey := []byte("secret")

	config := Config{
		ParseTokenFunc: func(c echo.Context, auth string) (interface{}, error) {
			keyFunc := func(t *jwt.Token) (interface{}, error) {
				if t.Method.Alg() != "HS256" {
					return nil, fmt.Errorf("unexpected jwt signing method=%v", t.Header["alg"])
				}
				return signingKey, nil
			}

			// claims are of type `jwt.MapClaims` when token is created with `jwt.Parse`
			token, err := jwt.Parse(auth, keyFunc)
			if err != nil {
				return nil, err
			}
			if !token.Valid {
				return nil, errors.New("invalid token")
			}
			return token, nil
		},
	}

	e.Use(WithConfig(config))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
	res := httptest.NewRecorder()
	e.ServeHTTP(res, req)

	assert.Equal(t, http.StatusTeapot, res.Code)
}

func TestMustJWTWithConfig_SuccessHandler(t *testing.T) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		success := c.Get("success").(string)
		user := c.Get("user").(string)
		return c.String(http.StatusTeapot, fmt.Sprintf("%v:%v", success, user))
	})

	mw, err := Config{
		ParseTokenFunc: func(c echo.Context, auth string) (interface{}, error) {
			return auth, nil
		},
		SuccessHandler: func(c echo.Context) {
			c.Set("success", "yes")
		},
	}.ToMiddleware()
	assert.NoError(t, err)
	e.Use(mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add(echo.HeaderAuthorization, "Bearer valid_token_base64")
	res := httptest.NewRecorder()
	e.ServeHTTP(res, req)

	assert.Equal(t, "yes:valid_token_base64", res.Body.String())
	assert.Equal(t, http.StatusTeapot, res.Code)
}

func TestJWTWithConfig_ContinueOnIgnoredError(t *testing.T) {
	var testCases = []struct {
		name                        string
		givenContinueOnIgnoredError bool
		givenErrorHandler           func(c echo.Context, err error) error
		givenTokenLookup            string
		whenAuthHeaders             []string
		whenCookies                 []string
		whenParseReturn             string
		whenParseError              error
		expectHandlerCalled         bool
		expect                      string
		expectCode                  int
	}{
		{
			name:                        "ok, with valid JWT from auth header",
			givenContinueOnIgnoredError: true,
			givenErrorHandler: func(c echo.Context, err error) error {
				return nil
			},
			whenAuthHeaders: []string{"Bearer valid_token_base64"},
			whenParseReturn: "valid_token",
			expectCode:      http.StatusTeapot,
			expect:          "valid_token",
		},
		{
			name:                        "ok, missing header, callNext and set public_token from error handler",
			givenContinueOnIgnoredError: true,
			givenErrorHandler: func(c echo.Context, err error) error {
				if errors.Is(err, ErrJWTMissing) {
					panic("must get ErrJWTMissing")
				}
				c.Set("user", "public_token")
				return nil
			},
			whenAuthHeaders: []string{}, // no JWT header
			expectCode:      http.StatusTeapot,
			expect:          "public_token",
		},
		{
			name:                        "ok, invalid token, callNext and set public_token from error handler",
			givenContinueOnIgnoredError: true,
			givenErrorHandler: func(c echo.Context, err error) error {
				// this is probably not realistic usecase. on parse error you probably want to return error
				if err.Error() != "parser_error" {
					panic("must get parser_error")
				}
				c.Set("user", "public_token")
				return nil
			},
			whenAuthHeaders: []string{"Bearer invalid_header"},
			whenParseError:  errors.New("parser_error"),
			expectCode:      http.StatusTeapot,
			expect:          "public_token",
		},
		{
			name:                        "nok, invalid token, return error from error handler",
			givenContinueOnIgnoredError: true,
			givenErrorHandler: func(c echo.Context, err error) error {
				if err.Error() != "parser_error" {
					panic("must get parser_error")
				}
				return err
			},
			whenAuthHeaders: []string{"Bearer invalid_header"},
			whenParseError:  errors.New("parser_error"),
			expectCode:      http.StatusInternalServerError,
			expect:          "{\"message\":\"Internal Server Error\"}\n",
		},
		{
			name:                        "nok, ContinueOnIgnoredError but return error from error handler",
			givenContinueOnIgnoredError: true,
			givenErrorHandler: func(c echo.Context, err error) error {
				return echo.ErrUnauthorized
			},
			whenAuthHeaders: []string{}, // no JWT header
			expectCode:      http.StatusUnauthorized,
			expect:          "{\"message\":\"Unauthorized\"}\n",
		},
		{
			name:                        "nok, ContinueOnIgnoredError=false",
			givenContinueOnIgnoredError: false,
			givenErrorHandler: func(c echo.Context, err error) error {
				return echo.ErrUnauthorized
			},
			whenAuthHeaders: []string{}, // no JWT header
			expectCode:      http.StatusUnauthorized,
			expect:          "{\"message\":\"Unauthorized\"}\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				token := c.Get("user").(string)
				return c.String(http.StatusTeapot, token)
			})

			mw, err := Config{
				ContinueOnIgnoredError: tc.givenContinueOnIgnoredError,
				TokenLookup:            tc.givenTokenLookup,
				ParseTokenFunc: func(c echo.Context, auth string) (interface{}, error) {
					return tc.whenParseReturn, tc.whenParseError
				},
				ErrorHandler: tc.givenErrorHandler,
			}.ToMiddleware()
			assert.NoError(t, err)
			e.Use(mw)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, a := range tc.whenAuthHeaders {
				req.Header.Add(echo.HeaderAuthorization, a)
			}
			res := httptest.NewRecorder()
			e.ServeHTTP(res, req)

			assert.Equal(t, tc.expect, res.Body.String())
			assert.Equal(t, tc.expectCode, res.Code)
		})
	}
}

func TestConfig_TokenLookupFuncs(t *testing.T) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		token := c.Get("user").(*jwt.Token)
		return c.JSON(http.StatusOK, token.Claims)
	})

	e.Use(WithConfig(Config{
		SigningKey: []byte("secret"),
		TokenLookupFuncs: []middleware.ValuesExtractor{
			func(c echo.Context) ([]string, error) {
				return []string{c.Request().Header.Get("X-API-Key")}, nil
			},
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
	res := httptest.NewRecorder()
	e.ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, `{"admin":true,"name":"John Doe","sub":"1234567890"}`+"\n", res.Body.String())
}

func TestWithConfig_panic(t *testing.T) {
	assert.PanicsWithError(t,
		"jwt middleware requires signing key",
		func() {
			WithConfig(Config{})
		},
	)
}
