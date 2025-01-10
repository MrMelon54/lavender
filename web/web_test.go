package web

import (
	"fmt"
	"github.com/1f349/lavender/utils"
	"github.com/stretchr/testify/assert"
	"html/template"
	"io/fs"
	"testing"
)

func TestLoadPages_FindErrors(t *testing.T) {
	glob, err := fs.Glob(webBuild, "dist/*/index.html")
	assert.NoError(t, err)

	fmt.Println(glob)

	for _, fileName := range glob {
		t.Run("Parsing "+fileName, func(t *testing.T) {
			_, err := template.New("web").Delims("[[", "]]").Funcs(template.FuncMap{
				"emailHide":         utils.EmailHide,
				"renderOptionTag":   renderOptionTag,
				"renderCheckboxTag": renderCheckboxTag,
			}).ParseFS(webBuild, fileName)
			assert.NoError(t, err)
		})
	}
}
