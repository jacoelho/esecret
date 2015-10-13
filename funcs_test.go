package esecret

import (
	"bytes"
	"log"
	"testing"
	"text/template"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	public_key  = "51565c4492373021baf9b1370b6ea4652afdd443d59991b855c59610943d8647"
	private_key = "ed9a6c2b4308c6492a297c2827d9374d9c17caaa9c48b1ba445ad8afb057e9d1"
)

type mockFile struct{}

func (f *mockFile) ReadFile(path string) (string, error) {
	return "", nil
}

func (f *mockFile) WriteFile(path string) {
	//
}

func (f *mockFile) ReadPrivateKey(keydir, pubkey string) (string, error) {
	return private_key, nil
}

func newMockContext() *ctx {
	return &ctx{
		file: &mockFile{},
	}
}

func TestFuncs(t *testing.T) {
	const templateText = `{{ public_key "51565c4492373021baf9b1370b6ea4652afdd443d59991b855c59610943d8647" }}\n{{ secret "foo" }}`

	c := newMockContext()
	tmpl, err := template.New("test").Funcs(c.newFuncMap()).Parse(templateText)
	if err != nil {
		log.Fatal("parsing: %s", err)
	}

	var data bytes.Buffer
	err = tmpl.Execute(&data, nil)
	Convey("should encryt", t, func() {
		So(err, ShouldBeNil)
		So(data.String(), ShouldContainSubstring, "EJ[1:")
	})
}

func TestInvalidPublicKey(t *testing.T) {
	const templateText = `{{ public_key "abcde" }}\n{{ secret "foobar" }}`

	c := newMockContext()
	tmpl, err := template.New("test").Funcs(c.newFuncMap()).Parse(templateText)
	if err != nil {
		log.Fatal("parsing: %s", err)
	}

	var data bytes.Buffer
	err = tmpl.Execute(&data, nil)
	Convey("should fail encryt", t, func() {
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "invalid key string")
	})
}

func TestEncryptedSuccess(t *testing.T) {
	const templateText = `{{ public_key "51565c4492373021baf9b1370b6ea4652afdd443d59991b855c59610943d8647" }}\n{{ encrypted "EJ[1:a+YQYN2SOgsJdOcl+O3zw4ZhGB9ig8dg0t1esbQBPCg=:mSv6DXTtgVoYP/Lpn0XJOGu2DDmF4KHL:wsOFWAbqG9tqLI68mjF9mwxTvg==]"  }}`

	c := newMockContext()
	tmpl, err := template.New("test").Funcs(c.newFuncMap()).Parse(templateText)
	if err != nil {
		log.Fatal("parsing: %s", err)
	}

	var data bytes.Buffer
	err = tmpl.Execute(&data, nil)
	Convey("should decrypt with success", t, func() {
		So(err, ShouldBeNil)
		So(data.String(), ShouldContainSubstring, "foo")
	})
}
