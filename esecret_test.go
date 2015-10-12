package esecret

import (
	"io/ioutil"
	"os"
	"regexp"
	"testing"

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
func TestDecryptFile(t *testing.T) {
	Convey("DecryptFile", t, func() {
		Convey("called with a non-existent file", func() {
			_, err := DecryptFile("/does/not/exist", "/doesnt/matter", false)
			Convey("should fail with ENOEXIST", func() {
				So(err.Error(), ShouldEqual, "open /does/not/exist: no such file or directory")
			})
		})

		Convey("called with an JSON file containing unencrypted-but-encryptable secrets", func() {
			Convey("should fail with a scary message", nil)
		})

		Convey("called with an invalid JSON file", func() {
			readFile = func(p string) ([]byte, error) {
				return []byte(`{{ invalid }}`), nil
			}
			_, err := DecryptFile("/doesnt/matter", "/doesnt/matter", false)
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
			_, err := DecryptFile("/doesnt/matter", "/doesnt/matter", false)
			readFile = ioutil.ReadFile
			Convey("should fail", func() {
				So(err, ShouldEqual, "cenas")
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "public key has invalid format")
			})
		})

		Convey("called with a valid keypair but no corresponding entry in keydir", func() {
			readFile = func(p string) ([]byte, error) {
				if p == "a" {
					return []byte(`{{ public_key "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d" }} {{ encrypted "a" }}`), nil
				}
				return ioutil.ReadFile("/does/not/exist")
			}
			_, err := DecryptFile("a", "b", false)
			readFile = ioutil.ReadFile
			Convey("should fail and describe that the key could not be found", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "couldn't read key file")
			})
		})

		Convey("called with a valid keypair and a corresponding entry in keydir", func() {
			readFile = func(p string) ([]byte, error) {
				if p == "a" {
					return []byte(`{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "EJ[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`), nil
				}
				return []byte("c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87"), nil
			}
			out, err := DecryptFile("a", "b", false)
			readFile = ioutil.ReadFile
			Convey("should fail and describe that the key could not be found", func() {
				So(err, ShouldBeNil)
				So(out, ShouldEqual, `{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`)
			})
		})

	})
}
