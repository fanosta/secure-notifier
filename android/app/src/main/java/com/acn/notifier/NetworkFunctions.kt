package com.acn.notifier

import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonObject
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.stream.Collectors

const val NETWORK_ENDPOINT_SEND = "https://acn.nageler.org/send";
const val NETWORK_ENDPOINT_GETTOKEN = "https://acn.nageler.org/get_token";

data class SenderToken(val Id: ByteArray, val PublicPoint: ByteArray, val Signature: ByteArray)

fun getSenderToken(recipient: ByteArray): SenderToken? {

    val recipientEncoded = Base64.encodeToString(recipient, Base64.URL_SAFE)
    val url = URL("$NETWORK_ENDPOINT_GETTOKEN/$recipientEncoded")
    val connection = url.openConnection() as HttpURLConnection
    connection.requestMethod = "GET"
    connection.doInput = true

    println(connection.responseCode)
    if (connection.responseCode >= 400) return null

    try{
        val stream = InputStreamReader(connection.inputStream)
        val jsonString: String = BufferedReader(stream).lines().collect(Collectors.joining("\n"))
        val result = Gson().fromJson(jsonString, JsonObject::class.java)

        return SenderToken(Base64.decode(result.get("sender_token_id").asString, Base64.NO_WRAP),
                           Base64.decode(result.get("public_point").asString, Base64.NO_WRAP),
                           Base64.decode(result.get("signature").asString, Base64.NO_WRAP))
    }
    catch (exception : java.lang.Exception) {
        Log.d("getSenderToken", "Error ${exception.message}")
    }

    return null
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