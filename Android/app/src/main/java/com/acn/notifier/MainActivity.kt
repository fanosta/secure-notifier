package com.acn.notifier

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.vision.barcode.Barcode

class MainActivity : Activity() {
  var textView: TextView? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    textView = findViewById(R.id.textView)
  }

  fun scanBarcode(view: View?) {
    val intent = Intent(this, ScannerActivity::class.java)
    startActivityForResult(intent, 0)
  }

  fun initKeyManager(view: View?) {
    val km = KeyManager(this)
    km.storeData("SECRET")
    textView!!.text = km.loadData()
  }

  fun openNetworkTestActivity(view: View?) {
    startActivity(Intent(this, NetworkTestActivity::class.java))
  }

  fun openMessengerActivity(view: View?) {
    startActivity(Intent(this, MessengerActivity::class.java))
  }

  override fun onActivityResult(
    requestCode: Int,
    resultCode: Int,
    data: Intent
  ) {
    super.onActivityResult(requestCode, resultCode, data)
    if (requestCode == 0) {
      if (resultCode == CommonStatusCodes.SUCCESS) {
        if (data != null) {
          val barcode: Barcode? = data.getParcelableExtra("received")
          textView!!.text = barcode?.displayValue
        } else {
          textView!!.text = "error occurred"
        }
      }
    }
  }
}