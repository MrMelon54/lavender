package web

import (
	"embed"
	"errors"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/utils"
	"github.com/1f349/overlapfs"
	"html"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var (
	//go:embed dist
	webBuild embed.FS

	webCombinedDir fs.FS
	pageTemplates  *template.Template
	loadOnce       utils.Once[error]
)

func LoadPages(wd string) error {
	return loadOnce.Do(func() (err error) {
		webCombinedDir = webBuild

		if wd != "" {
			webDir := filepath.Join(wd, "web")

			err = os.Mkdir(webDir, os.ModePerm)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}

			wdFs := os.DirFS(webDir)
			webCombinedDir = overlapfs.OverlapFS{A: webBuild, B: wdFs}
		}

		// TODO(melon): figure this out layer
		webCombinedDir = webBuild

		pageTemplates, err = template.New("web").Delims("[[", "]]").Funcs(template.FuncMap{
			"emailHide":         utils.EmailHide,
			"renderOptionTag":   renderOptionTag,
			"renderCheckboxTag": renderCheckboxTag,
		}).ParseFS(webCombinedDir, "dist/*.html")

		return err
	})
}

func renderOptionTag(value, display string, selectedValue string) template.HTML {
	var selectedParam string
	if value == selectedValue {
		selectedParam = " selected"
	}
	return template.HTML("<option value=\"" + html.EscapeString(value) + "\"" + selectedParam + ">" + html.EscapeString(display) + "</option>")
}

func renderCheckboxTag(name, id string, checked bool) template.HTML {
	var checkedParam string
	if checked {
		checkedParam = " checked"
	}
	return template.HTML("<input type=\"checkbox\" name=\"" + html.EscapeString(name) + "\" id=\"" + html.EscapeString(id) + "\"" + checkedParam + " />")
}

func RenderPageTemplate(wr io.Writer, name string, data any) {
	p := name + ".html"
	err := pageTemplates.ExecuteTemplate(wr, p, data)
	if err != nil {
		logger.Logger.Warn("Failed to render page", "name", name, "err", err)
	}
}

func RenderWebAsset(rw http.ResponseWriter, req *http.Request, name string) {
	// Disallow paths containing ".." - directory traversal is a security issue.
	if containsDotDot(name) {
		http.Error(rw, "400 Bad Request", http.StatusBadRequest)
	}

	// Disallow paths ending in ".html" - these should only be processed by HTML
	// template.
	if strings.HasSuffix(name, ".html") {
		http.Error(rw, "404 Not Found", http.StatusNotFound)
		return
	}

	// Enjoy the power of Go stdlib
	http.ServeFileFS(rw, req, webCombinedDir, name)
}

// Go stdlib net/http/fs.go (containsDotDot)
func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

// Go stdlib net/http/fs.go (isSlashRune)
func isSlashRune(r rune) bool { return r == '/' || r == '\\' }
