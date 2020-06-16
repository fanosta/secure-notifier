package com.acn.notifier

import android.content.Context
import android.widget.Toast
import java.lang.Exception

fun showToastMessage(applicationContext : Context, message : String) {
    val duration = Toast.LENGTH_LONG

    val toast = Toast.makeText(applicationContext, message, duration)
    toast.show()
}

class ToastException(message: String, causedBy: Exception? = null) : Exception(message) {
    val toastMessage = message
    val causedBy = causedBy
}