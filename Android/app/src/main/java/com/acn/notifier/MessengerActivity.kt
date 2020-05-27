package com.acn.notifier

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity


class MessengerActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_messenger)
    }

    fun sendMessage(view : View?) {
        var messageView = findViewById<TextView>(R.id.textNewMessage)
        var message = messageView.text;

        if(message.length <= 0) return;

        messageView.text = "";

        val container = findViewById<LinearLayout>(R.id.messageContainer)
        val newMessageLayout: View = LayoutInflater.from(this).inflate(R.layout.message_layout, container, false)

        val newMessageHeaderView = newMessageLayout.findViewById<TextView>(R.id.textViewHeader)
        val newMessageMessageView = newMessageLayout.findViewById<TextView>(R.id.textViewMessage)
        val newMessageFooterView = newMessageLayout.findViewById<TextView>(R.id.textViewFooter)

        newMessageHeaderView.setText("From: Sebastian")
        newMessageMessageView.setText(message)
        newMessageFooterView.setText("12:00")

        container.addView(newMessageLayout)

        println(message);
    }
}
