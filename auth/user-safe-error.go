package auth

import (
	"errors"
	"fmt"
	"net/http"
)

type UserSafeError struct {
	Display  string
	Code     int
	Internal error
}

func (e UserSafeError) Error() string {
	return fmt.Sprintf("%s [%d]: %v", e.Display, e.Code, e.Internal)
}

func (e UserSafeError) Unwrap() error {
	return e.Internal
}

func BasicUserSafeError(code int, message string) UserSafeError {
	return UserSafeError{
		Code:     code,
		Display:  message,
		Internal: errors.New(message),
	}
}

func AdminSafeError(inner error) UserSafeError {
	return UserSafeError{
		Code:     http.StatusInternalServerError,
		Display:  "Internal server error",
		Internal: inner,
	}
}
