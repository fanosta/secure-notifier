package com.acn.notifier

import android.app.Activity
import android.os.Bundle
import android.os.StrictMode
import android.util.JsonReader
import android.view.View
import android.widget.Button
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import kotlin.random.Random


class NetworkTestActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val policy = StrictMode.ThreadPolicy.Builder().permitAll().build()
        StrictMode.setThreadPolicy(policy)

        setContentView(R.layout.activity_network_test)
        requestAndShowNewFact(null);
    }

    fun requestAndShowNewFact(view: View?) {

        val responseFact = requestRandomFact();
        println(responseFact);

        findViewById<TextView>(R.id.serverMessage).text = responseFact
        findViewById<Button>(R.id.buttonNewMessage).text = getRandomButtonText()
    }

    private fun getRandomButtonText():String {
        val textSet = arrayOf("Go", "Next", "Tell me more", "Love it", "Go ahead", "Ok")
        return textSet[Random.nextInt(textSet.size)]
    }
}
