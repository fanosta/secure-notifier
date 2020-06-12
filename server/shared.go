package main

import (
	"crypto/ed25519"
	"encoding/json"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/sha3"

	"github.com/gorilla/websocket"
)

type ServerHello struct {
	ServerRandom string `json:"server_random"`
}

type ClientHello struct {
	ClientRandom string `json:"client_random"`
	PublicKey    string `json:"pubkey"`
}

type Signature struct {
	Signature string `json:"signature"`
}

type HandshakeFinished struct {
	Success bool `json:"success"`
	SendAllTokens bool `json:"send_all_tokens"`
}

type Error struct {
	Error string `json:"error"`
}

const MSGTYPE_INIT byte = 1
const MSGTYPE_ENCRYPTED byte = 2

type Message struct {
	Recipient []byte `json:"recipient"`
	Message   []byte `json:"msg"`
}

type SmallMessage struct {
	Message []byte `json:"msg"`
}

type QrCode struct {
	PublicKey []byte `json:"pubkey"`
	OnetimeKey []byte `json:"onetimekey"`
}

type SenderToken struct {
	Id            []byte `json:"sender_token_id"`
	PublicPoint   []byte `json:"public_point"`
	Signature     []byte `json:"signature"`
}

type PrivateSenderToken struct {
	SenderToken
	PrivateScalar []byte
}

func WriteJson(conn *websocket.Conn, h *hash.Hash, v interface{}) error {
	marshalled, err := json.Marshal(v)
	if err != nil {
		return err
	}
	// fmt.Println(string(marshalled))
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

func ReadJson(conn *websocket.Conn, h *hash.Hash, v interface{}) error {
	msgtype, marshalled, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if msgtype != websocket.TextMessage {
		return errors.New("wrong message type")
	}
	// fmt.Println(string(marshalled))

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

func HashTuple(messages ...[]byte) []byte {
	hash := sha3.New256()

	for _, msg := range messages {
		bytelen := make([]byte, 8)
		binary.LittleEndian.PutUint64(bytelen, uint64(len(msg)))
		hash.Write(bytelen)
		hash.Write(msg)
	}

	return hash.Sum(nil)
}

func SignWithContext(privkey ed25519.PrivateKey, msg []byte, transcriptHash []byte) []byte {
	sum := HashTuple([]byte("signature with transcript hash"), msg, transcriptHash)
	return ed25519.Sign(privkey, sum)
}

func VerifyWithContext(pubkey ed25519.PublicKey, msg []byte, transcriptHash []byte, signature []byte) bool {
	sum := HashTuple([]byte("signature with transcript hash"), msg, transcriptHash)
	return ed25519.Verify(pubkey, sum, signature)
}
