package esecret

import (
  "os"
  "testing"
  "log"
  "text/template"
//	. "github.com/smartystreets/goconvey/convey"
)

func TestFuncs(t *testing.T) {
  const templateText = `{{ secret "aadasa" }}\n{{ encrypted "coisas" }}`

  tmpl, err := template.New("test").Funcs(newFuncMap()).Parse(templateText)
  if err != nil {
    log.Fatal("parsing: %s", err)
  }

  err = tmpl.Execute(os.Stdout, nil)
  if err != nil {
    log.Fatal("execute: %s", err)
  }
}
