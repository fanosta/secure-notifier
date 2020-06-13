package com.acn.notifier

import android.os.Bundle
import android.os.StrictMode
import android.view.LayoutInflater
import android.view.View
import android.widget.DatePicker
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

        val key = km?.keyAgreement(ByteArray(32))
        pushMessageToServer(MessageElement("Sebastian", message, LocalDateTime.now().toString()))

        addGUIMessageElement("Sebastian", message, LocalDateTime.now().toString());

    }
}
