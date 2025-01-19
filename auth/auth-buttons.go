package auth

import (
	"context"
	"html/template"
	"net/http"
)

type Button interface {
	// ButtonName defines the text to show on the button.
	ButtonName() string

	// RenderButtonTemplate returns a template for the button widget.
	RenderButtonTemplate(ctx context.Context, req *http.Request) template.HTML
}
