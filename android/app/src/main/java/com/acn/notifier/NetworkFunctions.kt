package com.acn.notifier

import android.accounts.NetworkErrorException
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonObject
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.json.JSONObject
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.InputStreamReader
import java.io.Reader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets


const val NETWORK_ENDPOINT_SEND = "https://acn.nageler.org/send";
const val NETWORK_ENDPOINT_GETTOKEN = "https://acn.nageler.org/get_token";
const val randomFactsEndpoint = "https://uselessfacts.jsph.pl/random.json?language=";

data class SenderToken(val Id: ByteArray, val PublicPoint: ByteArray, val Signature: ByteArray)

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

fun getSenderToken(recipient: ByteArray): SenderToken {
    val url = URL(NETWORK_ENDPOINT_GETTOKEN  + "/" + Base64.encodeToString(recipient, Base64.DEFAULT))

    val connection = url.openConnection() as HttpURLConnection
    connection.requestMethod = "GET"
    connection.doInput = true

    if (connection.responseCode >= 400) {
        // TODO: proper error handling
        throw NetworkErrorException("got error while requesting sender token")
    }
    val stream = InputStreamReader(connection.inputStream)
    val result = Gson().fromJson(stream, SenderToken::class.java)

    // FIXME: verify signature

    return result

}

fun pushMessageToServer(messageElement: MessageElement) {
    val message = "{\"Message\": \"${messageElement.message}\", \"From\": \"${messageElement.from}\", \"Time\": \"${messageElement.footer}\"}"; //Use Gson().toJson ...
    println(message);

    val url = URL(NETWORK_ENDPOINT_SEND)
    val connection = url.openConnection() as HttpURLConnection
    connection.requestMethod = "POST"
    connection.doOutput = true

    val postData: ByteArray = message.toByteArray(StandardCharsets.UTF_8)

    connection.setRequestProperty("charset", "utf-8")
    connection.setRequestProperty("Content-length", postData.size.toString())
    connection.setRequestProperty("Content-Type", "application/json")

    val outputStream = DataOutputStream(connection.outputStream)
    outputStream.write(postData)
    outputStream.flush()

    println(connection.responseCode);
}

fun sendMessage(message: ByteArray, recipient: ByteArray) {
    val json = JsonObject()
    json.addProperty("recipient", Base64.encodeToString(recipient, Base64.DEFAULT))
    json.addProperty("msg", Base64.encodeToString(message, Base64.DEFAULT))

    val url = URL(NETWORK_ENDPOINT_SEND)
    val connection = url.openConnection() as HttpURLConnection
    connection.requestMethod = "POST"
    connection.doOutput = true

    val postData: ByteArray = json.toString().toByteArray()

    connection.setRequestProperty("charset", "utf-8")
    connection.setRequestProperty("Content-length", postData.size.toString())
    connection.setRequestProperty("Content-Type", "application/json")

    val outputStream = DataOutputStream(connection.outputStream)
    outputStream.write(postData)
    outputStream.flush()

    println(connection.responseCode)
    println(connection.responseMessage)
}