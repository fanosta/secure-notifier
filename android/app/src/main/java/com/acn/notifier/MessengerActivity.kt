package com.acn.notifier

import android.annotation.SuppressLint
import android.os.Bundle
import android.os.StrictMode
import android.util.Base64
import android.view.LayoutInflater
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
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

    @SuppressLint("SetTextI18n")
    fun addGUIMessageElement(from:String, message:String, footer:String) {

        val container = findViewById<LinearLayout>(R.id.messageContainer)
        val newMessageLayout: View = LayoutInflater.from(this).inflate(R.layout.message_layout, container, false)

        val newMessageHeaderView = newMessageLayout.findViewById<TextView>(R.id.textViewHeader)
        val newMessageMessageView = newMessageLayout.findViewById<TextView>(R.id.textViewMessage)
        val newMessageFooterView = newMessageLayout.findViewById<TextView>(R.id.textViewFooter)

        newMessageHeaderView.text = "From: $from"
        newMessageMessageView.text = message
        newMessageFooterView.text = footer

        container.addView(newMessageLayout)

    }

    fun sendTextMessage(view : View?) {

        val messageView = findViewById<TextView>(R.id.textNewMessage)
        val message = messageView.text.toString();

        if(message.isEmpty()) return;
        messageView.text = "";

        val result = sendMessage(applicationContext, km, message)

        if(result) {
            addGUIMessageElement("System", message, "Transferred to Server: ${LocalDateTime.now()}")
        }
        else {
            showToastMessage(this.applicationContext, "Hää 0.o - Message sending failed - try again")
        }
    }
}
