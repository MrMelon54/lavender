package utils

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEmailHide(t *testing.T) {
	require.Equal(t, "xx", EmailHide("hi"))
	require.Equal(t, "xxxxxxx@xxxxxxx.xxx", EmailHide("example@example.com"))
}
