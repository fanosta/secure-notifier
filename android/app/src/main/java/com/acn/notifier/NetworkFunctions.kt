package com.acn.notifier

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonObject
import okhttp3.*
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLPeerUnverifiedException


const val NETWORK_ENDPOINT = "https://acn.nageler.org/"
const val NETWORK_ENDPOINT_SEND = "https://acn.nageler.org/send"
const val NETWORK_ENDPOINT_GETTOKEN = "https://acn.nageler.org/get_token"

const val HOSTNAME = "acn.nageler.org"
val certificatePinner = CertificatePinner
    .Builder()
    .add(HOSTNAME, "sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")
    .add(HOSTNAME, "sha256/Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=")
    .build()

/*val certificatePinner = CertificatePinner
    .Builder()
    .add(HOSTNAME, "sha256/Egh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")
    .add(HOSTNAME, "sha256/Fss8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=")
    .build()*/

data class SenderToken(val Id: ByteArray, val PublicPoint: ByteArray, val Signature: ByteArray)


fun checkNetworkConnection(applicationContext:Context):Boolean{
    val connectivityManager = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val capabilities = connectivityManager.getNetworkCapabilities(connectivityManager.activeNetwork)
        ?: return false

    if(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return true
    if(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return true
    if(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return true
    if(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return true

    return false
}

fun endpointsAreAvailableAndValid() : Pair<Boolean, Boolean> {
    var available = false
    var verified = true

    try{
        val response = executeRequest(Request.Builder().url(NETWORK_ENDPOINT).build())
        available = response != null && response.isSuccessful

    } catch (sslException : SSLPeerUnverifiedException) {
        verified = false
        Log.d("Pinning", sslException.toString())
    } catch (exception : java.lang.Exception) {
        available = false
    }

    return Pair(available, verified)
}

fun postRequest(url: String, postContent : ByteArray, mediaType: MediaType? = MediaType.parse("application/json; charset=utf-8")) : Response? {
    if (mediaType == null) return null

    val body = RequestBody.create(mediaType, postContent)
    val request = Request.Builder().url(url).post(body).build()

    return try {
        executeRequest(request)
    } catch (exception: java.lang.Exception) {
        null
    }
}

fun getRequest(url: String) : Response? {
    return try {
        executeRequest(Request.Builder().url(url).build())
    } catch (exception: java.lang.Exception) {
        null
    }
}

@Throws(SSLPeerUnverifiedException::class)
private fun executeRequest(request:Request, timeout:Long = 5000) : Response? {
    val client = OkHttpClient
                .Builder()
                .certificatePinner(certificatePinner)
                .callTimeout(timeout, TimeUnit.MILLISECONDS)
                .build()

    try {
        return client.newCall(request).execute()
    } catch (sslException : SSLPeerUnverifiedException) {
        throw sslException
    } catch (exception : Exception) {
        Log.d("executeRequest", "Failed request due to: ${exception.message}")
    }

    return null
}

fun getSenderToken(recipient: Ed25519PublicKeyParameters): SenderToken? {

    val recipientEncoded = Base64.encodeToString(recipient.encoded, Base64.URL_SAFE)
    val response = getRequest("$NETWORK_ENDPOINT_GETTOKEN/$recipientEncoded")

    if (response != null && !response.isSuccessful) return null
    if (response!!.body() == null) return null

    try{
        val jsonString: String = response.body()!!.bytes().toString(Charsets.UTF_8)
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

fun sendEncryptedMessage(message: ByteArray, recipient: Ed25519PublicKeyParameters) : Boolean {
    val json = JsonObject()
    json.addProperty("recipient", Base64.encodeToString(recipient.encoded, Base64.DEFAULT))
    json.addProperty("msg", Base64.encodeToString(message, Base64.DEFAULT))

    val response = postRequest(NETWORK_ENDPOINT_SEND, json.toString().toByteArray())

    return response != null && response.isSuccessful
}
