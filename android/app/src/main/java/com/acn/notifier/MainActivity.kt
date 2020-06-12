package com.acn.notifier

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.TextView
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.vision.barcode.Barcode

class MainActivity : Activity() {
  var textView: TextView? = null
  var km: KeyManager? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    textView = findViewById(R.id.textView)
    km = KeyManager(this)
  }

  fun scanBarcode(view: View?) {
    val intent = Intent(this, ScannerActivity::class.java)
    startActivityForResult(intent, 0)
  }

  fun initKeyManager(view: View?) {

    textView!!.text = km?.loadData(km?.device_prkey_file)
    //val shared_key = km?.keyAgreement()
    //Log.d("DH", Base64.encodeToString(shared_key, Base64.DEFAULT))

    val messageToSign = "Hello"
    val sign1 = km?.sign(messageToSign)
    Log.d("Sign", "Sign 1: ${km?.sign(messageToSign)}\tSign1 still valid: ${km?.verifySign(messageToSign, sign1!!)}")
    Log.d("Sign", "Sign 2: ${km?.sign(messageToSign)}\tSign1 still valid: ${km?.verifySign(messageToSign, sign1!!)}")
    var km2 = KeyManager(this)
    Log.d("Sign", "Sign 3: ${km?.sign(messageToSign)}\tSign1 still valid: ${km?.verifySign(messageToSign, sign1!!)}")
    Log.d("Sign", "Sign 4: ${km?.sign(messageToSign)}\tSign1 still valid: ${km?.verifySign(messageToSign, sign1!!)}")

    /* message encrypt
    val message = "Message"
    Log.d("DH", message)
    var encrypted = km.encryptMessage(message, shared_key)
    Log.d("DH", encrypted)
    var decrypted = km.decryptMessage(encrypted, shared_key)
    Log.d("DH", decrypted)
    Log.d("DH", Base64.encodeToString(km.getIV(), Base64.DEFAULT))
     */
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
          km?.publicKeyExchange(barcode?.displayValue)
          textView!!.text = barcode?.displayValue
        } else {
          textView!!.text = "error occurred"
        }
      }
    }
  }
}