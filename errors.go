package echojwt

// TokenExtractionError is catch all type for all errors that occur when the token is extracted from the request. This
// helps to distinguish extractor errors from token parsing errors even if custom extractors or token parsing functions
// are being used that have their own custom errors.
type TokenExtractionError struct {
	Err error
}

// Is checks if target error is same as TokenExtractionError
func (e TokenExtractionError) Is(target error) bool { return target == ErrJWTMissing } // to provide some compatibility with older error handling logic

func (e *TokenExtractionError) Error() string { return e.Err.Error() }
func (e *TokenExtractionError) Unwrap() error { return e.Err }
