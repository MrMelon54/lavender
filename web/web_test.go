package web

import (
	"embed"
	"fmt"
	"github.com/1f349/lavender/utils"
	"github.com/stretchr/testify/assert"
	"html/template"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"
)

func TestLoadPages_FindErrors(t *testing.T) {
	glob, err := fs.Glob(webDist, "dist/*/index.html")
	assert.NoError(t, err)

	fmt.Println(glob)

	for _, fileName := range glob {
		t.Run("Parsing "+fileName, func(t *testing.T) {
			_, err := template.New("web").Delims("[[", "]]").Funcs(template.FuncMap{
				"emailHide":         utils.EmailHide,
				"renderOptionTag":   renderOptionTag,
				"renderCheckboxTag": renderCheckboxTag,
			}).ParseFS(webDist, fileName)
			assert.NoError(t, err)
		})
	}
}

//go:embed src/pages
var webSrcPages embed.FS

func TestLoadPage_FindMissing(t *testing.T) {
	paths := make([]string, 0)
	err := fs.WalkDir(webSrcPages, "src/pages", func(p string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path.Base(p), ".astro") {
			p = strings.TrimPrefix(p, "src/pages/")
			p = strings.TrimSuffix(p, ".astro")
			p += ".html"
			paths = append(paths, p)
		}
		return nil
	})
	assert.NoError(t, err)

	slices.Sort(paths)

	err = LoadPages("")
	assert.NoError(t, err)

	tmpls := make([]string, 0)

	for _, i := range pageTemplates.Templates() {
		if i.Name() == "" {
			continue
		}
		tmpls = append(tmpls, i.Name())
	}

	slices.Sort(tmpls)

	assert.ElementsMatch(t, paths, tmpls)
}
