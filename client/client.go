package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	_ "encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"html"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

const mintokens int = 16

var server = flag.String("server", "acn.nageler.org", "https service address")
var port = flag.Int("port", 443, "remote port")
var nohttps = flag.Bool("no-https", false, "use HTTP instead of HTTPS")

var new_client = flag.Bool("new-client", false, "pair a new client")

var peers []Peer

type DecryptedMessage struct {
	SenderPublicKey []byte
	SenderName string
	Message string
}

func authorize(conn *websocket.Conn, privkey ed25519.PrivateKey) (*HandshakeFinished, error) {
	transcriptHash := sha3.New256()
	var serverHello ServerHello

	err := ReadJson(conn, &transcriptHash, &serverHello)
	if err != nil {
		return nil, err
	}

	var clientHello ClientHello
	var random [32]byte
	_, err = rand.Read(random[:])
	if err != nil {
		return nil, err
	}
	clientHello.ClientRandom = base64.StdEncoding.EncodeToString(random[:])

	clientHello.PublicKey = base64.StdEncoding.EncodeToString(privkey.Public().(ed25519.PublicKey))

	err = WriteJson(conn, &transcriptHash, clientHello)
	if err != nil {
		return nil, err
	}

	signature := SignWithContext(privkey, []byte("identity assertion"), transcriptHash.Sum(nil))

	var signatureJson Signature
	signatureJson.Signature = base64.StdEncoding.EncodeToString(signature)

	err = WriteJson(conn, &transcriptHash, signatureJson)
	if err != nil {
		return nil, err
	}

	var handshakeFin HandshakeFinished
	err = ReadJson(conn, &transcriptHash, &handshakeFin)
	if err != nil {
		return nil, err
	}
	if !handshakeFin.Success {
		return nil, errors.New("server indicated failure")
	}

	return &handshakeFin, nil
}


func topUpTokens(tokens *[]PrivateSenderToken, privkey ed25519.PrivateKey, conn *websocket.Conn, filepath string) error {
	if len(*tokens) < mintokens {
		diff := mintokens - len(*tokens)

		newtokens, err := generateTokens(diff, privkey)

		if err != nil {
			return err
		}

		token_copy := make([]PrivateSenderToken, len(*tokens))
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

func pair(pubkey ed25519.PublicKey, init_channel chan []byte, new_peer_chan chan Peer) (error) {
	var qrCode QrCode

	qrCode.OnetimeKey = make([]byte, 16)

	_, err := rand.Read(qrCode.OnetimeKey[:])
	if err != nil {
		return err
	}

	qrCode.PublicKey = pubkey

	marshalled, err := json.Marshal(qrCode)
	if err != nil {
		return err
	}

	cmd := exec.Command("qrencode", "-tansi", string(marshalled))
	output, err := cmd.Output()

	if err != nil {
		fmt.Println("calling qrencode failed; you probably need to install it")
		return err
	}

	binary.Write(os.Stdout, binary.LittleEndian, output)

	msg := <-init_channel

	block_cipher, err := aes.NewCipher(qrCode.OnetimeKey)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block_cipher)
	if err != nil {
		panic(err.Error())
	}

	nonce := msg[:12]
	ciphertext := msg[12:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	if len(plaintext) != ed25519.PublicKeySize {
		return errors.New("peer send public key of invalid length")
	}

	peerPubkey := plaintext[:]

	if name, err := getPeerName(peerPubkey, peers); err == nil {
		fmt.Printf("peer %s is already known as %s\n", base64.StdEncoding.EncodeToString(peerPubkey), name)
		return nil
	}

	fmt.Printf("Enter a name for the new peer: ")
	reader := bufio.NewReader(os.Stdin)
	name, err := reader.ReadString('\n')
	if (err != nil) {
		return errors.New("reading name failed")
	}

	peer := Peer{Publickey: peerPubkey, Name: strings.TrimSpace(name)}
	new_peer_chan <- peer

	return nil
}


func decrypt_message(raw_message []byte, senderTokens *[]PrivateSenderToken) (*DecryptedMessage, error) {
	token_id := raw_message[0:32]
	sender_keyshare := raw_message[32:64]
	nonce := raw_message[64:76]
	ciphertext := raw_message[76:]

	privateToken, err := getToken(senderTokens, token_id)
	if err != nil {
		return nil, err
	}

	shared_key, err := curve25519.X25519(privateToken.PrivateScalar, sender_keyshare)
	if err != nil {
		return nil, err
	}

	block_cipher, err := aes.NewCipher(shared_key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block_cipher)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	signature := plaintext[:64]
	publickey := plaintext[64:96]
	msg := plaintext[96:]

	sendername, err := getPeerName(publickey, peers)
	if err != nil {
		return nil, err
	}

	hash := HashTuple([]byte("message signature"), token_id, msg)

	if !ed25519.Verify(publickey, hash, signature) {
		return nil, errors.New("signature verification failed")
	}

	result := DecryptedMessage {
		SenderPublicKey: publickey,
		SenderName: sendername,
		Message: string(msg),
	}

	return &result, nil
}


func main() {
	flag.Parse()
	log.SetFlags(0)

	cfg_path, err := os.UserConfigDir()
	cfg_dir := path.Join(cfg_path, "notifier")
	keypath := path.Join(cfg_dir, "key.json")
	tokenpath := path.Join(cfg_dir, "tokens.json")
	peerspath := path.Join(cfg_dir, "peers.json")

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

	peers, err = loadPeers(peerspath)
	if os.IsNotExist(err) {
		peers = []Peer{}
	} else if err != nil {
		log.Fatal("loadKey failed: ", err)
		os.Exit (1)
	}

	tokens, err := loadTokens(tokenpath)
	if os.IsNotExist(err) {
		tokens = []PrivateSenderToken{}
	} else if err != nil {
		log.Fatal("loadTokens failed: ", err)
		os.Exit (1)
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

	handshakeFin, err := authorize(c, privatekey)
	if err != nil {
		log.Fatal("authorize failed: ", err)
		return
	}
	log.Printf("authorization complete\n")

	if handshakeFin.SendAllTokens {
		c.WriteJSON(tokens)
	}

	init_chan := make(chan []byte)
	new_peer_chan := make(chan Peer)
	expecting_init_msg := false
	if *new_client || len(peers) == 0 {
		expecting_init_msg = true
		go func() {
			err := pair(privatekey.Public().(ed25519.PublicKey), init_chan, new_peer_chan)
			if (err != nil) {
				fmt.Printf("adding new peer failed: %s\n", err)
			}
		}()
	}

	msg_chan := make(chan []byte)
	go func() {
		for {
			if err := topUpTokens(&tokens, privatekey, c, tokenpath); err != nil {
				log.Fatal("topUpTokens failure", err)
				os.Exit(1)
			}
			var msg SmallMessage
			err := c.ReadJSON(&msg)
			if err != nil {
				log.Fatal("reading json failed: ", err)
				os.Exit(1)
			}
			msg_chan <- msg.Message
		}
	}()

	for {
		select {
		case peer := <-new_peer_chan:
			expecting_init_msg = false
			fmt.Printf("adding new peer: %s:%s\n", peer.Name, base64.StdEncoding.EncodeToString(peer.Publickey))
			peers = append(peers, peer)
			err = savePeers(peerspath, peers)
			if (err != nil) {
				log.Fatal("saving updated peer list failed", err)
				os.Exit(1)
			}

		case msg := <-msg_chan:
			msgtype := msg[0]
			msgcontent := msg[1:]
			var decrypted_msg *DecryptedMessage = nil
			err = nil
			switch msgtype {
				case MSGTYPE_INIT:
					if expecting_init_msg {
						init_chan <- msgcontent
					} else {
						fmt.Printf("unexpted init message\n")
					}
				case MSGTYPE_ENCRYPTED:
					decrypted_msg, err = decrypt_message(msgcontent, &tokens)
				default:
					fmt.Printf("unexpted message type: %d\n", msgtype)
			}

			if err != nil {
				fmt.Printf("Error while receiving message: %s\n", err)
			}

			if decrypted_msg != nil {
				fmt.Printf("%s: %s\n", decrypted_msg.SenderName, decrypted_msg.Message)

				if decrypted_msg.Message == "next" {
					cmd := exec.Command("xdotool", "key", "Page_Down")
					cmd.Run()
				} else if decrypted_msg.Message == "prev" {
					cmd := exec.Command("xdotool", "key", "Page_Up")
					cmd.Run()
				}
				{
					cmd := exec.Command("notify-send",
										decrypted_msg.SenderName,
										html.EscapeString(decrypted_msg.Message))
					cmd.Run()
				}
			}
		}
	}
}
