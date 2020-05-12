package com.acn.notifier

import android.app.Activity
import android.os.Bundle
import android.os.StrictMode
import android.util.JsonReader
import android.view.View
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL


class NetworkTestActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val policy = StrictMode.ThreadPolicy.Builder().permitAll().build()
        StrictMode.setThreadPolicy(policy)

        setContentView(R.layout.activity_network_test)
    }

    fun requestAndShowNewFact(view: View?) {
        var randomFactsEndpoint = "https://uselessfacts.jsph.pl/random.json?language=en";
        val connection:HttpURLConnection = URL(randomFactsEndpoint).openConnection() as HttpURLConnection

        var responseFact:String = "Sometimes there is no internet ..."

        try {
            responseFact = JSONObject(connection.inputStream.bufferedReader().readText()).getString("text").toString()
        }
        catch (e:Exception) {
            responseFact += "\nor just: " + e.message;
        }
        println(responseFact);

        findViewById<TextView>(R.id.serverMessage).text = responseFact;
    }
}
