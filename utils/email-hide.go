package utils

import "strings"

func EmailHide(email string) string {
	return strings.Map(func(r rune) rune {
		if r != '@' && r != '.' {
			return 'x'
		}
		return r
	}, email)
}
