package providers

import (
	"context"
	"errors"
	"fmt"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/database"
	"github.com/xlzd/gotp"
	"html/template"
	"net/http"
	"time"
)

func isDigitsSupported(digits int64) bool {
	return digits >= 6 && digits <= 8
}

type otpLoginDB interface {
	GetOtp(ctx context.Context, subject string) (database.GetOtpRow, error)
}

var _ auth.Provider = (*OtpLogin)(nil)

type OtpLogin struct {
	DB otpLoginDB
}

func (o *OtpLogin) AccessState() auth.State { return auth.StateBasic }

func (o *OtpLogin) Name() string { return "basic" }

func (o *OtpLogin) RenderTemplate(_ context.Context, _ *http.Request, user *database.User) (template.HTML, error) {
	if user == nil || user.Subject == "" {
		return "", fmt.Errorf("requires previous factor")
	}
	if user.OtpSecret == "" || !isDigitsSupported(user.OtpDigits) {
		return "", fmt.Errorf("user does not support factor")
	}

	// no need to provide render data
	return "<div>OTP login template</div>", nil
}

func (o *OtpLogin) AttemptLogin(ctx context.Context, req *http.Request, user *database.User) error {
	if user == nil || user.Subject == "" {
		return fmt.Errorf("requires previous factor")
	}
	if user.OtpSecret == "" || !isDigitsSupported(user.OtpDigits) {
		return fmt.Errorf("user does not support factor")
	}

	code := req.FormValue("code")

	if !validateTotp(user.OtpSecret, int(user.OtpDigits), code) {
		return auth.BasicUserSafeError(http.StatusBadRequest, "invalid OTP code")
	}
	return nil
}

var ErrInvalidOtpCode = errors.New("invalid OTP code")

func (o *OtpLogin) VerifyOtpCode(ctx context.Context, subject, code string) error {
	otp, err := o.DB.GetOtp(ctx, subject)
	if err != nil {
		return err
	}
	if !validateTotp(otp.OtpSecret, int(otp.OtpDigits), code) {
		return ErrInvalidOtpCode
	}
	return nil
}

func validateTotp(secret string, digits int, code string) bool {
	totp := gotp.NewTOTP(secret, int(digits), 30, nil)
	return verifyTotp(totp, code)
}

func verifyTotp(totp *gotp.TOTP, code string) bool {
	t := time.Now()
	if totp.VerifyTime(code, t) {
		return true
	}
	if totp.VerifyTime(code, t.Add(-30*time.Second)) {
		return true
	}
	return totp.VerifyTime(code, t.Add(30*time.Second))
}
