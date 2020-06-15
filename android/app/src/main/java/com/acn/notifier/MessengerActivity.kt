package com.acn.notifier

import android.os.Bundle
import android.os.StrictMode
import android.util.Base64
import android.view.LayoutInflater
import android.view.View
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

        if(!checkNetworkConnection(applicationContext)) {
            showToastMessage(applicationContext, "U are not connected to the Internet :O")
            return
        }

        if(!endpointsAreAvailable()) {
            showToastMessage(applicationContext, "We r unable to reach the Server :(")
            return
        }

        if(km == null) {
            showToastMessage(applicationContext, "Some internal KM problems :/")
            return
        }

        val recipientPublicKey = km!!.getPeerPublicKey()
        if(recipientPublicKey == null) {
            showToastMessage(applicationContext, "We forgot the recipient 0.o")
            return
        }

        val tripleResult = km!!.keyAgreement(recipientPublicKey)
        if(tripleResult == null) {
            showToastMessage(applicationContext, "We r unable to reach an agreement :|")
            return
        }

        val (key, sender_keyshare, token) = tripleResult
        println(Base64.encodeToString(key, Base64.DEFAULT))
        println(token)

        val msg_type = byteArrayOf(0x2)
        val token_id = token.Id

        val hash = km!!.hashTuple(
            ("message signature").toByteArray(),
            token_id,
            message.toByteArray()
        )

        val (_, publickey) = km!!.getDeviceKeyPair()
        val signature = km!!.signBytes(hash)

        val plaintext: ByteArray = signature + publickey.encoded + message.toByteArray()
        val (nonce, ciphertext) = km!!.encryptBytes(plaintext, key)

        sendEncryptedMessage(msg_type + token_id + sender_keyshare + nonce + ciphertext, recipientPublicKey)

        addGUIMessageElement("System", message, "Transferred to Server: ${LocalDateTime.now()}")
    }
}
