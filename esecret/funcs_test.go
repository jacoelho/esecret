package esecret

import (
	"log"
	"os"
	"testing"
	"text/template"
	//	. "github.com/smartystreets/goconvey/convey"
)

func TestFuncs(t *testing.T) {
	const templateText = `{{ encrypted "aadasa" }}\n{{ secret "coisas" }}`

	c := &ctx{}
	tmpl, err := template.New("test").Funcs(c.newFuncMap()).Parse(templateText)
	if err != nil {
		log.Fatal("parsing: %s", err)
	}

	err = tmpl.Execute(os.Stdout, nil)
	if err != nil {
		log.Fatal("execute: %s", err)
	}
}
