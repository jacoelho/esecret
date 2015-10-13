package esecret

import (
	"bytes"
	"log"
	"testing"
	"text/template"

	. "github.com/smartystreets/goconvey/convey"
)

func TestFuncs(t *testing.T) {
	const templateText = `{{ public_key "9d623862e8ae8f908d5df97b2f4647789cfbf2f9c6c3f175eb9181cdb7602b5d" }}\n{{ secret "foo" }}`

	c := &ctx{}
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

	c := &ctx{}
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

func TestEncrypted(t *testing.T) {
	const templateText = `{{ public_key "9d623862e8ae8f908d5df97b2f4647789cfbf2f9c6c3f175eb9181cdb7602b5d" }}\n{{ encrypted "EJ[1:SNTch6oV3xMTE3MAiWttlkTKRWDpWe525uJ5PUMI3XY=:zYVXMRG1n77sSFp8ERGtwfEKs8gRxZ6I:E6T+esQ0/Fp19yB7Oy0dgJKw0w==]"  }}`

	c := &ctx{}
	tmpl, err := template.New("test").Funcs(c.newFuncMap()).Parse(templateText)
	if err != nil {
		log.Fatal("parsing: %s", err)
	}

	var data bytes.Buffer
	err = tmpl.Execute(&data, nil)
	Convey("should fail to decrypt", t, func() {
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "couldn't decrypt message")
	})
}
