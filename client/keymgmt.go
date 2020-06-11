package main

import (
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"

	"golang.org/x/crypto/curve25519"
)

type KeyStruct struct {
	PrivateKey []byte `json:"privatekey"`
}
type Peer struct {
	Name string `json:"name"`
	Publickey []byte `json:"publickey"`
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

func generateAndSaveKey(filePath string) (ed25519.PrivateKey, error) {
	var keyStruct KeyStruct
	keyStruct.PrivateKey = make([]byte, ed25519.SeedSize)


	marshalled, err := json.MarshalIndent(keyStruct, "", "  ")

	if err != nil {
		return nil, err
	}

	if err := ioutil.WriteFile(filePath, marshalled, 0600); err != nil {
		return nil, err
	}

	return ed25519.NewKeyFromSeed(keyStruct.PrivateKey), nil
}

func loadTokens(filePath string) ([]PrivateSenderToken, error) {
	var tokens []PrivateSenderToken

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &tokens)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func generateTokens(numtokens int, privkey ed25519.PrivateKey) ([]PrivateSenderToken, error) {
	tokens := make([]PrivateSenderToken, numtokens)


	for i := range tokens {
		var err error
		tokens[i].Id = make([]byte, 32)
		tokens[i].PrivateScalar = make([]byte, 32)

		if _, err = rand.Read(tokens[i].Id[:]); err != nil {
			return nil, err
		}
		if _, err = rand.Read(tokens[i].PrivateScalar[:]); err != nil {
			return nil, err
		}

		tokens[i].PublicPoint, err = curve25519.X25519(tokens[i].PrivateScalar, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}

		hash := HashTuple([]byte("sender token"), tokens[i].Id, tokens[i].PublicPoint)

		tokens[i].Signature = ed25519.Sign(privkey, hash)
	}

	return tokens, nil
}

func getToken(tokens *[]PrivateSenderToken, id []byte) (PrivateSenderToken, error) {
	var result PrivateSenderToken

	tokenIndex := -1
	for i, token := range *tokens {
		if subtle.ConstantTimeCompare(token.Id, id) == 1 {
			tokenIndex = i
			break
		}
	}

	if tokenIndex == -1 {
		return result, errors.New("Sender token not found")
	}

	result = (*tokens)[tokenIndex]
	*tokens = append((*tokens)[:tokenIndex], (*tokens)[tokenIndex + 1:]...)

	return result, nil
}

func saveTokens(filePath string, tokens []PrivateSenderToken) error {
	marshalled, err := json.MarshalIndent(tokens, "", "  ")

	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filePath, marshalled, 0600); err != nil {
		return err
	}

	return nil
}

func loadPeers(filePath string) ([]Peer, error) {
	var peers []Peer
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &peers)
	if err != nil {
		return nil, err
	}

	return peers, nil
}

func savePeers(filePath string, peers []Peer) error {
	marshalled, err := json.MarshalIndent(peers, "", "  ")

	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filePath, marshalled, 0600); err != nil {
		return err
	}

	return nil
}
