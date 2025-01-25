package login_process

import "github.com/1f349/mjwt"

var _ mjwt.Claims = (*LoginProcessData)(nil)

// TODO: add some actual session management
type LoginProcessData struct {
	State byte
}

func (d LoginProcessData) Valid() error { return nil }

func (d LoginProcessData) Type() string { return "login-process" }
