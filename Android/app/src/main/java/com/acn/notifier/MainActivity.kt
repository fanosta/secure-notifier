package com.acn.notifier

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.SeekBar
import android.widget.TextView

class MainActivity : AppCompatActivity() {

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)

    val button = findViewById<Button>(R.id.button)
    val textview = findViewById<TextView>(R.id.textView)
    val seekbar = findViewById<SeekBar>(R.id.seekBar)

    button.setOnClickListener {
        var num = seekbar.progress
        textview.text = num.toString()
    }
  }
}
