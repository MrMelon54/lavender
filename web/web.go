package web

import (
	"embed"
	"errors"
	"github.com/1f349/lavender/logger"
	"github.com/1f349/lavender/utils"
	"github.com/1f349/overlapfs"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
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
		webCombinedDir, err = fs.Sub(webBuild, "dist")
		if err != nil {
			return err
		}

		if wd != "" {
			webDir := filepath.Join(wd, "web")

			err = os.Mkdir(webDir, os.ModePerm)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}

			wdFs := os.DirFS(webDir)
			webCombinedDir = overlapfs.OverlapFS{A: webBuild, B: wdFs}
		}

		pageTemplates, err = template.New("web").Delims("[[", "]]").Funcs(template.FuncMap{
			"emailHide": utils.EmailHide,
			"renderTitle":
		}).ParseFS(webCombinedDir, "*/index.html")

		return err
	})
}

func renderTitle(title string, service string) string {
	
}

func RenderPageTemplate(wr io.Writer, name string, data any) {
	p := path.Join(name, "index.html")
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
