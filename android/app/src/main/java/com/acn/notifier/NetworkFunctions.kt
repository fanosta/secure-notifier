package com.acn.notifier

import android.accounts.NetworkErrorException
import android.util.Base64
import com.google.gson.Gson
import com.google.gson.JsonObject
import org.json.JSONObject
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.stream.Collectors


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
    val url = URL(NETWORK_ENDPOINT_GETTOKEN  + "/" + Base64.encodeToString(recipient, Base64.NO_WRAP))
    println(url)
    val connection = url.openConnection() as HttpURLConnection
    connection.requestMethod = "GET"
    connection.doInput = true

    println(connection.responseCode)
    if (connection.responseCode >= 400) {
        // TODO: proper error handling
        throw NetworkErrorException("got error while requesting sender token")
    }
    val stream = InputStreamReader(connection.inputStream)
    val tmp: String = BufferedReader(stream).lines().collect(Collectors.joining("\n"))
    println(tmp)
    val result = Gson().fromJson(tmp, JsonObject::class.java)
    println(result)

    var sender_token: SenderToken = SenderToken(
        Base64.decode(result.get("sender_token_id").asString, Base64.NO_WRAP),
        Base64.decode(result.get("public_point").asString, Base64.NO_WRAP),
        Base64.decode(result.get("signature").asString, Base64.NO_WRAP))

    println(sender_token)
    return sender_token

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

fun sendEncryptedMessage(message: ByteArray, recipient: ByteArray) {
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