package com.acn.notifier

import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

const val NETWORK_ENDPOINT = "https://sebastianknoll.net/studium/acn/";
const val randomFactsEndpoint = "https://uselessfacts.jsph.pl/random.json?language=";


fun requestRandomFact(languageString:String = "en"):String {
    val connection: HttpURLConnection = URL(randomFactsEndpoint + languageString).openConnection() as HttpURLConnection

    var responseFact:String = "Sometimes there is no internet ..."

    try {
        responseFact = JSONObject(connection.inputStream.bufferedReader().readText()).getString("text").toString()
    }
    catch (e:Exception) {
        responseFact += "\nor just: " + e.message;
    }

    return responseFact;
}

fun requestServerMessages():Collection<MessageElement> {
    val connection: HttpURLConnection = URL(NETWORK_ENDPOINT).openConnection() as HttpURLConnection
    val messageElements = mutableListOf<MessageElement>();

    val jsonMessages = JSONObject(URL(NETWORK_ENDPOINT).readText()).getJSONArray("Messages");

    for(index in 0 until jsonMessages.length()) {
        val jsonMessage = jsonMessages.getJSONObject(index);
        messageElements.add(
            MessageElement(
                jsonMessage.getString("From"),
                jsonMessage.getString("Message"),
                jsonMessage.getString("Time")
            )
        )
    }

    return messageElements;
}