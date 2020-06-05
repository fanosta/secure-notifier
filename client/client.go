package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	_ "encoding/hex"
	"flag"
	"log"
	"net/url"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/sha3"
)

var addr = flag.String("addr", "localhost:8080", "http service address")

func authorize(conn *websocket.Conn, privkey ed25519.PrivateKey) error {
	transcriptHash := sha3.New256()
	var serverHello ServerHello

	err := ReadJson(conn, &transcriptHash, &serverHello)
	if err != nil {
		return err
	}

	var clientHello ClientHello
	var random [32]byte
	_, err = rand.Read(random[:])
	if err != nil {
		return err
	}
	clientHello.ClientRandom = base64.RawStdEncoding.EncodeToString(random[:])

	clientHello.PublicKey = base64.RawStdEncoding.EncodeToString(privkey.Public().(ed25519.PublicKey))

	err = WriteJson(conn, &transcriptHash, clientHello)
	if err != nil {
		return err
	}

	signature := SignWithContext(privkey, []byte("identity assertion"), transcriptHash.Sum(nil))

	var signatureJson Signature
	signatureJson.Signature = base64.RawStdEncoding.EncodeToString(signature)

	err = WriteJson(conn, &transcriptHash, signatureJson)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	_, privatekey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("keygen failed: ", err)
	}

	u := url.URL{Scheme: "ws", Host: *addr, Path: "/ws"}
	log.Printf("connecting to %s", u.String())

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial: ", err)
	}
	defer c.Close()

	err = authorize(c, privatekey)
	if err != nil {
		log.Fatal("authorize failed: ", err)
	}
}
