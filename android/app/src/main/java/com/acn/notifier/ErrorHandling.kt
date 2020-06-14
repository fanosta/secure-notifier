package com.acn.notifier

import android.content.Context
import android.widget.Toast

fun showToastMessage(applicationContext : Context, message : String) {
    val duration = Toast.LENGTH_LONG

    val toast = Toast.makeText(applicationContext, message, duration)
    toast.show()
}