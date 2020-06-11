package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	_ "encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os/exec"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/sha3"
)

var server = flag.String("server", "acn.nageler.org", "https service address")
var port = flag.Int("port", 443, "remote port")
var nohttps = flag.Bool("no-https", false, "use HTTP instead of HTTPS")

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
	clientHello.ClientRandom = base64.StdEncoding.EncodeToString(random[:])

	clientHello.PublicKey = base64.StdEncoding.EncodeToString(privkey.Public().(ed25519.PublicKey))

	err = WriteJson(conn, &transcriptHash, clientHello)
	if err != nil {
		return err
	}

	signature := SignWithContext(privkey, []byte("identity assertion"), transcriptHash.Sum(nil))

	var signatureJson Signature
	signatureJson.Signature = base64.StdEncoding.EncodeToString(signature)

	err = WriteJson(conn, &transcriptHash, signatureJson)
	if err != nil {
		return err
	}

	var handshakeFin HandshakeFinished
	err = ReadJson(conn, &transcriptHash, &handshakeFin)
	if err != nil {
		return err
	}
	if !handshakeFin.Success {
		return errors.New("server indicated failure")
	}

	return nil
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	privatekey, err := loadKey("/home/marcel/.acnkey")
	if err != nil {
		log.Fatal("loadKey failed: ", err)
	}

	fmt.Printf("public key: %s\n", base64.StdEncoding.EncodeToString(privatekey.Public().(ed25519.PublicKey)))

	var scheme string
	if *nohttps {
		scheme = "ws"
	} else {
		scheme = "wss"
	}

	u := url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%d", *server, *port), Path: "/ws"}
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

	for {
		var msg SmallMessage
		err := c.ReadJSON(&msg)
		if err != nil {
			log.Fatal("reading json failed: ", err)
			return
		}
		fmt.Println(string(msg.Message))
		cmd := exec.Command("notify-send", "ACN", string(msg.Message))
		cmd.Run()
	}
}
