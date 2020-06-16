package com.acn.notifier

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.StrictMode
import android.view.View

class SlidesActivity : AppCompatActivity() {
    var km: KeyManager? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_slides)

        val policy = StrictMode.ThreadPolicy.Builder().permitAll().build()
        StrictMode.setThreadPolicy(policy)
        km = KeyManager(this.applicationContext)
    }

    private fun requestSlide(slide : String, command : String) {
        try {
            if (!sendMessage(applicationContext, km!!, command)) {
                showToastMessage(applicationContext, "Failed requesting $slide slide :/")
            }
        } catch (e: ToastException) {
            showToastMessage(applicationContext, e.toastMessage)
        }
    }

    fun requestPreviousSlide(view : View?) {
        requestSlide("Previous", "prev")
    }

    fun requestNextSlide(view : View?) {
        requestSlide("Next", "next")
    }
}