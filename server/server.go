package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	// "os"
	//"io"

	"golang.org/x/crypto/sha3"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

////////////////////////////////////////////////////////////////////////////////
// global vars
////////////////////////////////////////////////////////////////////////////////
var queuedMessages map[[32]byte] [][]byte
var messagesMut sync.Mutex

var channels map[[32]byte]chan []byte
var channelsMut sync.RWMutex

var senderTokens map[[32]byte] []SenderToken
var tokensMut sync.Mutex

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

	pubkey, err := base64.StdEncoding.DecodeString(clientHello.PublicKey)
	if err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(signatureJson.Signature)

	if !VerifyWithContext(pubkey, []byte("identity assertion"), authorizeHash, signature) {
		fmt.Printf("verify failed\n")
		return nil, errors.New("signature verification failed")
	}

	var handshakeFin HandshakeFinished
	handshakeFin.Success = true
	err = WriteJson(conn, &transcriptHash, handshakeFin)
	if err != nil {
		return nil, err
	}

	return pubkey, nil
}

var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func pubkeyAsBytes(pubkey ed25519.PublicKey) [32]byte {
	var res [32]byte
	copy(res[:], pubkey[:])
	return res
}

func queueMessage(recipient [32]byte, msg []byte) {
	messagesMut.Lock()
	queuedMessages[recipient] = append(queuedMessages[recipient], msg)
	messagesMut.Unlock()
}

func submitMessage(recipient [32]byte, msg []byte) {
	channelsMut.RLock()
	channel, ok := channels[recipient]
	if ok {
		channel <- msg
		channelsMut.RUnlock()
		return
	}
	channelsMut.RUnlock()

	queueMessage(recipient, msg)
}

func readPump(conn *websocket.Conn, pubkey ed25519.PublicKey) {
	defer conn.Close()

	pubkeyarr := pubkeyAsBytes(pubkey)

	// ensure map entry for sendertokens exists
	tokensMut.Lock()
	_, ok := senderTokens[pubkeyarr]
	if !ok {
		senderTokens[pubkeyarr] = make([]SenderToken, 0)
	}
	tokensMut.Unlock()

	for {
		var newTokens []SenderToken
		err := conn.ReadJSON(&newTokens)
		if err != nil {
			fmt.Printf("error: %v", err)
			break
		}
		
		tokensMut.Lock()
		senderTokens[pubkeyarr] = append(senderTokens[pubkeyarr], newTokens...)
		fmt.Printf("%s\n", senderTokens[pubkeyarr])
		tokensMut.Unlock()
	}
}
func writePump(conn *websocket.Conn, pubkey ed25519.PublicKey) {
	ticker := time.NewTicker(30 * time.Second)
	var err error
	defer ticker.Stop()

	channelsMut.Lock()
	var pubkeyArr [32]byte
	copy(pubkeyArr[:], pubkey[:])
	channel := make(chan []byte)
	channels[pubkeyArr] = channel
	channelsMut.Unlock()

	cleanup := func() {
		channelsMut.Lock()
		close(channel)
		delete(channels, pubkeyArr)
		channelsMut.Unlock()

		for msg := range channel {
			queueMessage(pubkeyArr, msg)
		}
	}
	defer cleanup()

	messagesMut.Lock()
	var newQueue [][]byte = nil
	for _, msg := range queuedMessages[pubkeyArr] {
		// FIXME: not getting delivered?
		err = conn.WriteJSON(Message{Recipient: pubkeyArr[:], Message: msg})
		if err != nil {
			newQueue = append(newQueue, msg)
		}
	}
	queuedMessages[pubkeyArr] = newQueue
	messagesMut.Unlock()

	if newQueue != nil {
		return
	}

	for {
		select {
		case msg := <-channel:
			err = conn.WriteJSON(SmallMessage{Message: msg})
			if err != nil {
				queueMessage(pubkeyArr, msg)
				return
			}
		case <-ticker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func wshandler(w http.ResponseWriter, r *http.Request) {
	conn, err := wsupgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	pubkey, err := authorize(conn)
	if err != nil {
		conn.WriteJSON(Error{err.Error()})
		return
	}
	fmt.Printf("successfully verified %s\n", base64.StdEncoding.EncodeToString(pubkey))

	go writePump(conn, pubkey)
	go readPump(conn, pubkey)
}

func sendMessage(c *gin.Context) {
	var msg Message
	err := c.ShouldBind(&msg)
	if err != nil {

		c.JSON(422, Error{err.Error()})
		//c.JSON(422, strToMsg("invalid json"))
		return
	}

	if len(msg.Recipient) != 32 {
		c.JSON(422, Error{"invalid recipient length"})
		return
	}

	var recipientArr [32]byte
	copy(recipientArr[:], msg.Recipient[:])

	fmt.Println(msg.Recipient)
	fmt.Println(msg.Message)
	submitMessage(recipientArr, msg.Message)

	c.JSON(201, strToMsg("msg submitted"))
}

func getToken(c *gin.Context) {
	var token SenderToken
	pubkey, err := base64.StdEncoding.DecodeString(c.Params.ByName("pubkey"))
	if err != nil || len(pubkey) != 32 {
		c.JSON(422, strToMsg("invalid public key"))
		return
	}

	var pubkeyarr [32]byte
	copy(pubkeyarr[:], pubkey[:])

	tokensMut.Lock()
	defer tokensMut.Unlock()

	tokens, ok := senderTokens[pubkeyarr]

	fmt.Printf("ok: %b, tokens: %s\n", ok, tokens)

	if ok && len(tokens) > 1 {
		token = tokens[0]
		senderTokens[pubkeyarr] = tokens[1:]
		c.JSON(200, token)
		return
	}

	c.JSON(404, strToMsg("no sender tokens available"))
}


func main() {
	port := 8080
	queuedMessages = make(map[[32]byte][][]byte)
	channels = make(map[[32]byte]chan []byte)
	senderTokens = make(map[[32]byte] []SenderToken)

	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, strToMsg("hello world"))
	})
	r.POST("/send", sendMessage)
	r.GET("/get_token/:pubkey", getToken)

	r.GET("/ws", func(c *gin.Context) {
		wshandler(c.Writer, c.Request)
	})

	r.NoRoute(func(c *gin.Context) {
		c.JSON(404, strToMsg("invalid api endpoint"))
	})

	r.Run(fmt.Sprintf(":%d", port))
}
