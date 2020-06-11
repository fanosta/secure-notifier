package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io/ioutil"
)

type KeyStruct struct {
	PrivateKey []byte `json:"privatekey"`
}

func loadKey(filePath string) (ed25519.PrivateKey, error) {
	var keyStruct KeyStruct

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &keyStruct)
	if err != nil {
		return nil, err
	}

	if len(keyStruct.PrivateKey) != ed25519.SeedSize {
		return nil, errors.New("invalid private key length")
	}

	return ed25519.NewKeyFromSeed(keyStruct.PrivateKey), nil
}
