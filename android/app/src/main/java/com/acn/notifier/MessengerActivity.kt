package com.acn.notifier

import android.os.Bundle
import android.os.StrictMode
import android.util.Base64
import android.view.LayoutInflater
import android.view.View
import android.widget.DatePicker
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.time.LocalDateTime


class MessengerActivity : AppCompatActivity() {
    var km: KeyManager? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_messenger)

        val policy = StrictMode.ThreadPolicy.Builder().permitAll().build()
        StrictMode.setThreadPolicy(policy)
        km = KeyManager(this.applicationContext)
    }

    fun addGUIMessageElement(from:String, message:String, footer:String) {

        val container = findViewById<LinearLayout>(R.id.messageContainer)
        val newMessageLayout: View = LayoutInflater.from(this).inflate(R.layout.message_layout, container, false)

        val newMessageHeaderView = newMessageLayout.findViewById<TextView>(R.id.textViewHeader)
        val newMessageMessageView = newMessageLayout.findViewById<TextView>(R.id.textViewMessage)
        val newMessageFooterView = newMessageLayout.findViewById<TextView>(R.id.textViewFooter)

        newMessageHeaderView.setText("From: " + from)
        newMessageMessageView.setText(message)
        newMessageFooterView.setText(footer)

        container.addView(newMessageLayout)

    }

    fun sendMessage(view : View?) {
        var messageView = findViewById<TextView>(R.id.textNewMessage)
        var message = messageView.text.toString();

        if(message.length <= 0) return;

        messageView.text = "";

        val recipientPublicKey = km?.loadData(km?.pubkey_file)
        println(recipientPublicKey)

        if (recipientPublicKey != null && km != null) {

            val (key, sender_keyshare, token) = km!!.keyAgreement(Base64.decode(recipientPublicKey, Base64.DEFAULT))

            println(Base64.encodeToString(key, Base64.DEFAULT))
            println(token)
            /*
              token_id := raw_message[0:32]
              sender_keyshare := raw_message[32:64]
              nonce := raw_message[64:88]
              ciphertext := raw_message[88:]

              signature := plaintext[:64]
              publickey := plaintext[64:96]
              msg := plaintext[96:]
             */
            var msg_type = byteArrayOf(0x2)
            var token_id = token?.Id
            var recipient = km!!.getRecipientPublicKey()
            if (token_id != null && sender_keyshare != null && recipient != null) {
                val hash = km!!.hashTuple(
                    ("message signature").toByteArray(),
                    token_id,
                    message.toByteArray()
                )
                val publickey = km!!.getDeviceKeyPair().public as Ed25519PublicKeyParameters
                val signature = km!!.sign(hash.toString())
                val plaintext: ByteArray = signature + publickey.encoded + message.toByteArray()
                var (nonce, ciphertext) = km!!.encryptBytes(plaintext, key)
                sendEncryptedMessage(msg_type + sender_keyshare + nonce + ciphertext, recipient)
            } else {

            }

        } else {

        }

        //pushMessageToServer(MessageElement("Sebastian", message, LocalDateTime.now().toString()))

        //addGUIMessageElement("Sebastian", message, LocalDateTime.now().toString());

    }
}
