package esecret

import (
  "os"
  "regexp"
  "testing"
  "io/ioutil"

  . "github.com/smartystreets/goconvey/convey"
)

func TestEncryptFileInPlace(t *testing.T) {
  getMode = func(p string) (os.FileMode, error) {
    return 0400, nil
  }
  defer func() { getMode = _getMode }()
  Convey("EncryptFileInPlace", t, func() {
    Convey("called with a non-existent file", func() {
      _, err := EncryptFileInPlace("/does/not/exist")
      Convey("should fail with ENOEXIST", func() {
        So(os.IsNotExist(err), ShouldBeTrue)
      })
    })

    Convey("called with an invalid template file", func() {
      readFile = func(p string) ([]byte, error) {
        return []byte(`#{{ public_key "asdasdada" }}\n{{ unknown "123123" }}`), nil
      }
      _, err := EncryptFileInPlace("/doesnt/matter")
      readFile = ioutil.ReadFile
      Convey("should fail", func() {
        So(err, ShouldNotBeNil)
        So(err.Error(), ShouldContainSubstring, "not defined")
      })
    })

    Convey("called with an invalid keypair", func() {
      readFile = func(p string) ([]byte, error) {
        return []byte(`{{ public_key "invalid" }}`), nil
      }
      _, err := EncryptFileInPlace("/doesnt/matter")
      readFile = ioutil.ReadFile
      Convey("should fail", func() {
        So(err, ShouldNotBeNil)
        So(err.Error(), ShouldEqual, "open /doesnt/matter: no such file or directory")
      })
    })

    Convey("called with a valid keypair", func() {
      readFile = func(p string) ([]byte, error) {
        return []byte(`{{ public_key "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d" }}{{ secret "a" }}{{ secret "b" }}`), nil
      }
      var output []byte
      writeFile = func(path string, data []byte, mode os.FileMode) error {
        output = data
        return nil
      }
      _, err := EncryptFileInPlace("/doesnt/matter")
      readFile = ioutil.ReadFile
      writeFile = ioutil.WriteFile
      Convey("should encrypt the file", func() {
        So(err, ShouldBeNil)
        match := regexp.MustCompile(`{{ public_key "8d8.*" }}{{ encrypted "EJ.*" }}`)
        So(match.Find(output), ShouldNotBeNil)
      })
    })

  })
}
