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
	"os"
	"os/exec"
	"path"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/sha3"
)

const mintokens int = 16

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


func topUpTokens(tokens *[]PrivateSenderToken, privkey ed25519.PrivateKey, conn *websocket.Conn, filepath string) error {
	if len(*tokens) < mintokens {
		diff := mintokens - len(*tokens)

		log.Printf("generating %d new tokens\n", diff)
		newtokens, err := generateTokens(diff, privkey)

		if err != nil {
			return err
		}

		token_copy := make([]PrivateSenderToken, mintokens)
		copy(token_copy, *tokens)

		token_copy = append(token_copy, newtokens...)
		err = saveTokens(filepath, token_copy)
		if err != nil {
			return err
		}

		err = conn.WriteJSON(newtokens)
		if err != nil {
			return err
		}

		*tokens = token_copy
	}

	return nil
}


func main() {
	flag.Parse()
	log.SetFlags(0)

	cfg_path, err := os.UserConfigDir()
	cfg_dir := path.Join(cfg_path, "notifier")
	keypath := path.Join(cfg_dir, "key.json")
	tokenpath := path.Join(cfg_dir, "tokens.json")

	if _, err := os.Stat(cfg_dir); os.IsNotExist(err) {
		os.Mkdir(cfg_dir, 0700)
	}

	privatekey, err := loadKey(keypath)
	if os.IsNotExist(err) {
		fmt.Printf("%s does not exist, generating a new one\n", keypath)
		privatekey, err = generateAndSaveKey(keypath)
		if err != nil {
			log.Fatal("keygen failed: ", err)
			os.Exit (1)
		}
	} else if err != nil {
		log.Fatal("loadKey failed: ", err)
	}

	tokens, err := loadTokens(tokenpath)
	if os.IsNotExist(err) {
		tokens = []PrivateSenderToken{}
	} else if err != nil {
		log.Fatal("loadKey failed: ", err)
		os.Exit (1)
	}
	fmt.Printf("read tokens: %s\n", tokens)

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

	err = c.WriteJSON(tokens)

	for {
		if err := topUpTokens(&tokens, privatekey, c, tokenpath); err != nil {
			log.Fatal("topUpTokens failure", err)
			return
		}
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
