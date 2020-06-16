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
        var toastString = "Failed requesting $slide slide :/";
        if(sendMessage(applicationContext, km, command)) {
            toastString = "$slide slide - Check :D"
        }

        showToastMessage(applicationContext, toastString)
    }

    fun requestPreviousSlide(view : View?) {
        requestSlide("Previous", "prev")
    }

    fun requestNextSlide(view : View?) {
        requestSlide("Next", "next")
    }
}