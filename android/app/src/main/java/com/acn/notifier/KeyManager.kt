package com.acn.notifier

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.google.gson.*
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.lang.reflect.Type
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

val customGson: Gson = GsonBuilder().registerTypeHierarchyAdapter(
    ByteArray::class.java,
    ByteArrayToBase64TypeAdapter()
).create()

private class ByteArrayToBase64TypeAdapter : JsonSerializer<ByteArray?>,
    JsonDeserializer<ByteArray?> {
    @Throws(JsonParseException::class)
    override fun deserialize(
        json: JsonElement,
        typeOfT: Type?,
        context: JsonDeserializationContext?
    ): ByteArray {
        return Base64.decode(json.getAsString(), Base64.NO_WRAP)
    }

    override fun serialize(
        src: ByteArray?,
        typeOfSrc: Type?,
        context: JsonSerializationContext?
    ): JsonElement {
        return JsonPrimitive(Base64.encodeToString(src, Base64.NO_WRAP))
    }
}

data class KeyManagerStruct(var PrivateKey: ByteArray?, var PeerPublicKey: ByteArray?)

class KeyManager(appContext: Context) {
    val km_tag = "KeyManager"
    val key_name = "file_key"
    val ks: KeyStore

    var configFile: File? = null
    var config: KeyManagerStruct? = null

    var pubkey_file: File? = null
    var device_prkey_file: File? = null


    init {
        val path = appContext.filesDir
        val keyDirectory = File(path, "key")
        keyDirectory.mkdirs()

        configFile = File(keyDirectory, "config.json.enc")

        pubkey_file = File(keyDirectory, "pubkey.txt")
        device_prkey_file = File(keyDirectory, "device_prkey_spec.txt")

        ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)

        if (!ks.containsAlias(key_name)) {
            val generator: KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")

            generator.init (
                KeyGenParameterSpec.Builder (
                    key_name, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
            )
            generator.generateKey()
            Log.d(km_tag, "key generated")
        } else {
            Log.d(km_tag, "key already exists")
        }

        try {
            readConfig()
        } catch (ex: java.io.FileNotFoundException) {
            config = KeyManagerStruct(null, null)
            writeConfig()
        }
    }

    private fun getEncCipher(): Cipher {
        val secretKey = ks.getKey(key_name, null) as SecretKey
        val cipherInstance = Cipher.getInstance("AES/GCM/NoPadding")
        cipherInstance.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipherInstance
    }
    private fun getDecCipher(nonce: ByteArray): Cipher {
        val secretKey = ks.getKey(key_name, null) as SecretKey
        val cipherInstance = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipherInstance.init(Cipher.DECRYPT_MODE, secretKey, spec)
        return cipherInstance
    }

    private fun writeToFile(data: ByteArray, file: File?) {
        val cipher = getEncCipher()
        val encryptedData = cipher.doFinal(data)

        FileOutputStream(file).use {
            it.write(cipher.iv)
            it.write(encryptedData)
        }
    }

    private fun readFromFile(file: File?): ByteArray {
        var fileContents: ByteArray? = null
        fileContents = FileInputStream(file).use {
            it.readBytes()
        }

        val nonce = fileContents.copyOfRange(0, 12)
        val data = fileContents.copyOfRange(12, fileContents.size)

        val cipher = getDecCipher(nonce)
        val decryptedData = cipher.doFinal(data)

        return decryptedData
    }

    private fun readConfig() {
        val fileContents = readFromFile(configFile).toString(Charsets.UTF_8)
        config = customGson.fromJson(fileContents, KeyManagerStruct::class.java)
    }

    private fun writeConfig() {
        val fileContents = customGson.toJson(config)
        writeToFile(fileContents.toByteArray(), configFile)
    }

    private fun generateED25519KeyPair() : Pair<Ed25519PrivateKeyParameters, Ed25519PublicKeyParameters> {
        val keyPairGenerator = Ed25519KeyPairGenerator()
        val random = SecureRandom()

        keyPairGenerator.init(KeyGenerationParameters(random, 0))

        Log.d("DeviceKeyPair", "Generated new ED25519 KeyPair")
        val keypair = keyPairGenerator.generateKeyPair()
        return Pair(keypair.private as Ed25519PrivateKeyParameters, keypair.public as Ed25519PublicKeyParameters)
    }

    fun getDeviceKeyPair(): Pair<Ed25519PrivateKeyParameters, Ed25519PublicKeyParameters> {
        val private = getDevicePrivateKey()
        val public = private.generatePublicKey()

        return Pair(private, public)
    }

    fun getDevicePrivateKey(): Ed25519PrivateKeyParameters {
        readConfig()
        if (config?.PrivateKey?.isEmpty() != false)
        {
            val (private, public) = generateED25519KeyPair()
            config?.PrivateKey = private.encoded
            writeConfig()
        }
        return Ed25519PrivateKeyParameters(config?.PrivateKey, 0)
    }

    fun getPeerPublicKey(): Ed25519PublicKeyParameters? {
        readConfig()
        if (config?.PeerPublicKey?.isEmpty() != false)
        {
            return null
        }
        return Ed25519PublicKeyParameters(config?.PeerPublicKey, 0)
    }

    fun savePeerPublicKey(pubkey: Ed25519PublicKeyParameters) {
        readConfig()
        config?.PeerPublicKey = pubkey.encoded;
        writeConfig()
    }

    fun signBytes(messageBytes : ByteArray) : ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, getDevicePrivateKey())
        signer.update(messageBytes, 0, messageBytes.size)

        return signer.generateSignature()
    }

    private fun generateX25519KeyPair(): Pair<X25519PrivateKeyParameters, X25519PublicKeyParameters> {
        val key_pair_generator = X25519KeyPairGenerator()
        val secure_random = SecureRandom()
        val params = KeyGenerationParameters(secure_random, 0)
        key_pair_generator.init(params)

        val key_pair: AsymmetricCipherKeyPair = key_pair_generator.generateKeyPair()

        val private = key_pair.private as X25519PrivateKeyParameters
        val public = key_pair.public as X25519PublicKeyParameters

        return Pair(private, public)
    }

    private fun getSharedSecret(public_key: X25519PublicKeyParameters, private_key: X25519PrivateKeyParameters): ByteArray {
        val key_agreement = X25519Agreement()
        key_agreement.init(private_key)
        key_agreement.agreementSize
        val shared_key = ByteArray(key_agreement.agreementSize)
        key_agreement.calculateAgreement(public_key, shared_key, 0)

        return shared_key
    }

    fun hashTuple(vararg messages: ByteArray): ByteArray
    {
        val hash: DigestSHA3 = SHA3.Digest256()

        for (msg in messages) {
            val bytelen: ByteBuffer = ByteBuffer.allocate(8)
            bytelen.order(ByteOrder.LITTLE_ENDIAN)
            bytelen.putLong(msg.size.toLong())
            hash.update(bytelen.array())
            hash.update(msg)
        }
        return hash.digest()
    }

    fun keyAgreement(recipientPublicKey: Ed25519PublicKeyParameters): Triple<ByteArray, ByteArray, SenderToken>? {
        // get token id + public key
        val token = getSenderToken(recipientPublicKey) ?: return null

        val hash = hashTuple(("sender token").toByteArray(), token.Id, token.PublicPoint)

        val verifier = Ed25519Signer()
        verifier.init(false, recipientPublicKey)
        verifier.update(hash, 0, hash.size)

        if (!verifier.verifySignature(token.Signature))
            return null

        val server_public_key = X25519PublicKeyParameters(ByteArrayInputStream(token.PublicPoint))

        val (private, public) = generateX25519KeyPair()

        // encrypt message with shared key
        val shared_key = getSharedSecret(server_public_key, private)

        return Triple(shared_key, public.encoded, token)
    }

    fun encryptBytes(data: ByteArray, shared_key: ByteArray): Pair<ByteArray, ByteArray> {
        val secret_key: SecretKey = SecretKeySpec(shared_key, 0, shared_key.size, "AES")
        val cipher_instance = Cipher.getInstance("AES/GCM/NoPadding")
        cipher_instance.init(Cipher.ENCRYPT_MODE, secret_key)

        val encrypted_message = cipher_instance.doFinal(data)

        return Pair(cipher_instance.iv, encrypted_message)
    }

    fun publicKeyExchange(scan_result: String?) {
        Log.d(km_tag, scan_result)

        val json: JsonObject = Gson().fromJson(scan_result, JsonObject::class.java)
        val peerPubkey = Base64.decode(json.get("pubkey").asString, Base64.DEFAULT)
        val peerPubkeyEd25519 = Ed25519PublicKeyParameters(ByteArrayInputStream(peerPubkey))

        savePeerPublicKey(peerPubkeyEd25519)

        val onetimekey = Base64.decode(json.get("onetimekey").asString, Base64.DEFAULT)

        val msg_type = byteArrayOf(0x1)
        val (_, mypubkey) = getDeviceKeyPair()

        val (nonce, ciphertext) = encryptBytes(mypubkey.encoded, onetimekey);

        sendEncryptedMessage(msg_type + nonce + ciphertext, peerPubkeyEd25519);
    }
}