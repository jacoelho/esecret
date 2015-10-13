package esecret

import (
	"bytes"
	"io/ioutil"
	"os"
	"text/template"
)

func getMode(path string) (os.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode(), nil
}

func EncryptFileInPlace(filePath string) (int, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return -1, err
	}

	context := newCtx("", false)
	tmpl, err := template.New("").Funcs(context.newFuncMap()).Parse(string(data))
	if err != nil {
		return -1, err
	}
	var newdata bytes.Buffer
	err = tmpl.Execute(&newdata, nil)
	if err != nil {
		return -1, err
	}

	fileMode, err := getMode(filePath)
	if err != nil {
		return -1, err
	}

	if err := ioutil.WriteFile(filePath, newdata.Bytes(), fileMode); err != nil {
		return -1, err
	}

	return len(newdata.Bytes()), nil
}

func DecryptFile(filePath, keydir string, machine bool) (string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	context := newCtx(keydir, machine)
	tmpl, err := template.New("").Funcs(context.newFuncMap()).Parse(string(data))
	if err != nil {
		return "", err
	}
	var newdata bytes.Buffer
	err = tmpl.Execute(&newdata, nil)
	if err != nil {
		return "", err
	}

	return newdata.String(), nil
}
