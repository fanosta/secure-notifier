package main


import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"hash"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/gorilla/websocket"
)

type ServerHello struct {
	ServerRandom string `json:"server_random"`
}

type ClientHello struct {
	ClientRandom string `json:"client_random"`
	PublicKey string `json:"pubkey"`
}

type Signature struct {
	Signature string `json:"signature"`
}

type Error struct {
	Error string `json:"error"`
}

type Message struct {
	recipient [32]byte;
	message   []byte;
}


func WriteJson(conn *websocket.Conn, h *hash.Hash, v interface {}) error {
	marshalled, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Println(string(marshalled))
	_, err = (*h).Write(marshalled)
	if err != nil {
		return err
	}
	err = conn.WriteMessage(websocket.TextMessage, marshalled)
	if err != nil {
		return err
	}

	return nil
}

func ReadJson(conn *websocket.Conn, h *hash.Hash, v interface {}) error {
	msgtype, marshalled, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if msgtype != websocket.TextMessage {
		return errors.New("wrong message type")
	}
	fmt.Println(string(marshalled))

	_, err = (*h).Write(marshalled)
	if err != nil {
		return err
	}

	err = json.Unmarshal(marshalled, v)
	if err != nil {
		return err
	}

	return nil
}

func SignWithContext(privkey ed25519.PrivateKey, msg []byte, transcriptHash []byte) []byte {
	hmac := hmac.New(sha3.New256, transcriptHash)

	hmac.Write(msg)
	sum := hmac.Sum(nil)

	return ed25519.Sign(privkey, sum)
}

func VerifyWithContext(pubkey ed25519.PublicKey, msg []byte, transcriptHash []byte, signature []byte) bool {
	hmac := hmac.New(sha3.New256, transcriptHash)

	hmac.Write(msg)
	sum := hmac.Sum(nil)

	return ed25519.Verify(pubkey, sum, signature)
}
