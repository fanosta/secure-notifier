package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/crypto/sha3"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

////////////////////////////////////////////////////////////////////////////////
// global vars
////////////////////////////////////////////////////////////////////////////////
var messages map[[32]byte]Message
var messagesMut sync.RWMutex

var empty struct{}

func strToMsg(s string) gin.H {
	return gin.H{
		"messages": []string{s},
	}
}

func authorize(conn *websocket.Conn) (ed25519.PublicKey, error) {
	transcriptHash := sha3.New256()

	var serverHello ServerHello

	var random [32]byte
	_, err := rand.Read(random[:])
	if err != nil {
		return nil, err
	}
	serverHello.ServerRandom = base64.StdEncoding.EncodeToString(random[:])

	err = WriteJson(conn, &transcriptHash, serverHello)
	if err != nil {
		return nil, err
	}

	var clientHello ClientHello
	err = ReadJson(conn, &transcriptHash, &clientHello)
	if err != nil {
		return nil, err
	}

	authorizeHash := transcriptHash.Sum(nil)

	var signatureJson Signature
	err = ReadJson(conn, &transcriptHash, &signatureJson)
	if err != nil {
		return nil, err
	}

	pubkey, err := base64.RawStdEncoding.DecodeString(clientHello.PublicKey)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawStdEncoding.DecodeString(signatureJson.Signature)

	if !VerifyWithContext(pubkey, []byte("identity assertion"), authorizeHash, signature) {
		fmt.Printf("verify failed\n")
		return nil, errors.New("signature verification failed")
	}

	return pubkey, nil
}

var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func wshandler(w http.ResponseWriter, r *http.Request) {
	conn, err := wsupgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	pubkey, err := authorize(conn)
	if err != nil {
		conn.WriteJSON(Error{err.Error()})
		return
	}

	fmt.Printf("successfully verified %s\n", base64.RawStdEncoding.EncodeToString(pubkey))
}

func main() {
	port := 8080

	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, strToMsg("hello world"))
	})

	r.GET("/ws", func(c *gin.Context) {
		wshandler(c.Writer, c.Request)
	})

	r.NoRoute(func(c *gin.Context) {
		c.JSON(404, strToMsg("invalid api endpoint"))
	})

	r.Run(fmt.Sprintf(":%d", port))
}
