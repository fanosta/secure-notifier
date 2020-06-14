package com.acn.notifier

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.opengl.Visibility
import android.os.Bundle
import android.os.StrictMode
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.TextView
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.vision.barcode.Barcode

class MainActivity : Activity() {
  var statusText: TextView? = null
  var buttonMessenger: Button? = null
  var km: KeyManager? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val policy = StrictMode.ThreadPolicy.Builder().permitAll().build()
    StrictMode.setThreadPolicy(policy)
    setContentView(R.layout.activity_main)
    statusText = findViewById(R.id.statusText)
    buttonMessenger = findViewById(R.id.buttonMessenger)
    km = KeyManager(this.applicationContext)

    setStatusText()
  }

  private fun setStatusText() {
    var status = "Use 'Scan QR-Code' to connect to a Client"
    buttonMessenger!!.visibility = View.GONE

    if(km != null && km!!.getRecipientPublicKey() != null) {
      status = "You are connected with:\n\n"
      status += Base64.encodeToString(km!!.getRecipientPublicKey(), Base64.DEFAULT)
      status += "\n\nUse 'Messenger' to send messages"
      status += "\n\nOr use 'Scan QR-Code' to connect to a new Client"
      buttonMessenger!!.visibility = View.VISIBLE
    }

    if(statusText == null) {
      statusText!!.visibility = View.GONE
      return
    }

    statusText!!.visibility = View.VISIBLE
    statusText!!.text = status
  }

  fun scanBarcode(view: View?) {
    val intent = Intent(this, ScannerActivity::class.java)
    startActivityForResult(intent, 0)
  }

  fun openMessengerActivity(view: View?) {
    startActivity(Intent(this, MessengerActivity::class.java))
  }

  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    super.onActivityResult(requestCode, resultCode, data)
    if (requestCode == 0) {
      if (resultCode == CommonStatusCodes.SUCCESS) {
        if (data != null) {
          val barcode: Barcode? = data.getParcelableExtra("received")
          km?.publicKeyExchange(barcode?.displayValue)
        }
      }
    }

    setStatusText()
  }
}