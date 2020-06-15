# Android: Notifier (Server) 
Receiving notifications from mobile phone on a computer client using a web server while ensuring that all transfered data is encrypted.

#### Repository
.
├── android   (android client in Kotlin)
├── client    (desktop client in Go)
├── server    (server in Go)
├── slides

#### Message
* msg_type
  0x1 = init
  0x2 = encrypted msg

* message type init 
  nonce := msg[:12]
  ciphertext := msg[12:]

  publickey = plaintext

* message type encrypted
  token_id := raw_message[0:32]
  sender_keyshare := raw_message[32:64]
  nonce := raw_message[64:88]
  ciphertext := raw_message[88:]

  signature := plaintext[:64]
  publickey := plaintext[64:96]
  msg := plaintext[96:]
