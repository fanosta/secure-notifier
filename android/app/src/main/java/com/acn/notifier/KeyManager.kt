package com.acn.notifier

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonObject
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class KeyManager(mainActivity: MainActivity) {

    val km_tag = "KeyManager"
    val key_name = "file_key"
    val ks: KeyStore
    var pubkey_file: File? = null
    var device_prkey_file: File? = null
    var iv: ByteArray? = null
    var device_kp: AsymmetricCipherKeyPair? = null

    init {
        val context = mainActivity.applicationContext
        val path = context.getFilesDir()
        val keyDirectory = File(path, "key")
        keyDirectory.mkdirs()

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
    }

    fun getIV(): ByteArray? {
        return iv
    }

    private fun encryptData(data: String): String {
        val secret_key = ks.getKey(key_name, null) as SecretKey
        val cipher_instance = Cipher.getInstance("AES/GCM/NoPadding")
        cipher_instance.init(Cipher.ENCRYPT_MODE, secret_key)
        iv = cipher_instance.getIV()

        val encrypted_data = cipher_instance.doFinal(data.toByteArray())
        val encoded_data = Base64.encodeToString(encrypted_data, Base64.DEFAULT)

        return encoded_data
    }

    private fun decryptData(data: String): String {
        val decoded_data = Base64.decode(data, Base64.DEFAULT)

        val secret_key = ks.getKey(key_name, null) as SecretKey
        val cipher_instance = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher_instance.init(Cipher.DECRYPT_MODE, secret_key, spec)

        val decrypted_data = cipher_instance.doFinal(decoded_data)

        return String(decrypted_data, Charsets.UTF_8)
    }

    private fun writeToFile(encrypted_data: String, file: File?) {
        val enc_iv = Base64.encodeToString(iv, Base64.DEFAULT)
        val write_to_file = enc_iv.plus(encrypted_data)

        FileOutputStream(file).use {
            it.write(write_to_file.toByteArray())
        }
    }

    private fun readFromFile(file: File?): String? {
        var read_from_file: String? = null
        try {
             read_from_file = FileInputStream(file).bufferedReader().use {
                it.readText() }
        }
        catch (ex: java.lang.Exception)
        {
            Log.d(km_tag, "File does not exist")
        }
        if (read_from_file != null) {
            val split = read_from_file.split('\n', limit = 2)
            iv = Base64.decode(split.get(0).toByteArray(), Base64.DEFAULT)
            Log.d(km_tag, split.get(1))
            return split.get(1)
        }
        return null
    }

    fun storeData(data: String, file: File?) {
        Log.d(km_tag, "storeData")
        val encrypted_data = encryptData(data)
        writeToFile(encrypted_data, file)
    }

    fun loadData(file: File?): String {
        Log.d(km_tag, "loadData")
        val encrypted_data = readFromFile(file)
        if (encrypted_data != null)
            return decryptData(encrypted_data)
        else
            return "empty file"
    }

    private fun generateED25519KeyPair() : AsymmetricCipherKeyPair {
        val keyPairGenerator = Ed25519KeyPairGenerator()
        val nonce = SecureRandom()

        keyPairGenerator.init(KeyGenerationParameters(nonce, 0))

        Log.d("DeviceKeyPair", "Generated new ED25519 KeyPair")
        return keyPairGenerator.generateKeyPair()
    }

    private fun loadDeviceKeyPairFromFile() : AsymmetricCipherKeyPair? {
        var keyPair: AsymmetricCipherKeyPair? = null

        try {
            val privateKeyParameters = Gson().fromJson(loadData(device_prkey_file), Ed25519PrivateKeyParameters::class.java)
            device_kp = AsymmetricCipherKeyPair(privateKeyParameters.generatePublicKey(), privateKeyParameters)
        }
        catch (exception : Exception) {
            Log.d("DeviceKeyPair", "Unable to load existing KeyPair from file due to: ${exception.message}")
        }

        return keyPair
    }

    private fun storeDeviceKeyPairToFile() {
        if(device_kp == null) return

        storeData(Gson().toJson(device_kp!!.private as Ed25519PrivateKeyParameters), device_prkey_file)
        Log.d("DeviceKeyPair", "Stored KeyPair to encrypted File")
    }

    fun getDeviceKeyPair() : AsymmetricCipherKeyPair {
        if(device_kp != null) return device_kp!!

        device_kp = loadDeviceKeyPairFromFile()
        if(device_kp != null) return device_kp!!

        device_kp = generateED25519KeyPair()
        storeDeviceKeyPairToFile()
        return device_kp!!
    }

    fun sign(message : String) : ByteArray {
        val messageBytes = message.toByteArray()

        val signer = Ed25519Signer()
        signer.init(true, getDeviceKeyPair().private as Ed25519PrivateKeyParameters)
        signer.update(messageBytes, 0, messageBytes.size)

        return signer.generateSignature()
    }

    fun verifySign(message: String, signature: ByteArray) : Boolean {
        val messageBytes = message.toByteArray()

        val verifier = Ed25519Signer()
        verifier.init(false, getDeviceKeyPair().public as Ed25519PublicKeyParameters)
        verifier.update(messageBytes, 0, messageBytes.size)

        return verifier.verifySignature(signature)
    }

    // TODO: replace with real SenderToken
    private fun getSenderToken(): AsymmetricKeyParameter {
        val key_pair: AsymmetricCipherKeyPair = generateX25519KeyPair()

        return key_pair.getPublic()
    }

    private fun generateX25519KeyPair(): AsymmetricCipherKeyPair {
        val key_pair_generator = X25519KeyPairGenerator()
        val secure_random = SecureRandom()
        val params = KeyGenerationParameters(secure_random, 0)
        key_pair_generator.init(params)

        val key_pair: AsymmetricCipherKeyPair = key_pair_generator.generateKeyPair()

        return key_pair
    }

    private fun getSharedSecret(public_key: AsymmetricKeyParameter, private_key: AsymmetricKeyParameter): ByteArray {
        val key_agreement = X25519Agreement()
        key_agreement.init(private_key)
        key_agreement.agreementSize
        val shared_key = ByteArray(key_agreement.agreementSize)
        key_agreement.calculateAgreement(public_key, shared_key, 0)

        return shared_key
    }

    fun keyAgreement(): ByteArray {
        // get token id + public key
        val server_public_key: AsymmetricKeyParameter = getSenderToken()

        val key_pair: AsymmetricCipherKeyPair = generateX25519KeyPair()
        // send client_public_key to server
        val client_public_key: AsymmetricKeyParameter = key_pair.getPublic()
        val client_private_key: AsymmetricKeyParameter = key_pair.getPrivate()
        // encrypt message with shared key
        val shared_key = getSharedSecret(server_public_key, client_private_key)

        return shared_key
    }

    fun hashTuple(vararg messages: ByteArray): ByteArray
    {
        val hash: DigestSHA3 = SHA3.Digest256()

        for (msg in messages) {
            val bytelen: ByteBuffer = ByteBuffer.allocate(8)
            bytelen.order(ByteOrder.LITTLE_ENDIAN)
            bytelen.putInt((msg.size))
            hash.update(bytelen.array())
            hash.update(msg)
        }
        return hash.digest()
    }

    fun encryptMessage(data: String, shared_key: ByteArray): String {
        val secret_key: SecretKey = SecretKeySpec(shared_key, 0, shared_key.size, "AES")
        val cipher_instance = Cipher.getInstance("AES/GCM/NoPadding")
        cipher_instance.init(Cipher.ENCRYPT_MODE, secret_key)
        iv = cipher_instance.getIV()

        val encrypted_message = cipher_instance.doFinal(data.toByteArray())
        val encoded_message = Base64.encodeToString(encrypted_message, Base64.DEFAULT)

        return encoded_message
    }

    fun decryptMessage(data: String, shared_key: ByteArray): String {
        val decoded_message = Base64.decode(data, Base64.DEFAULT)

        val secret_key: SecretKey = SecretKeySpec(shared_key, 0, shared_key.size, "AES")
        val cipher_instance = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher_instance.init(Cipher.DECRYPT_MODE, secret_key, spec)

        val decrypted_message = cipher_instance.doFinal(decoded_message)

        return String(decrypted_message, Charsets.UTF_8)
    }

    fun publicKeyExchange(scan_result: String?) {
        Log.d(km_tag, scan_result)

        val json: JsonObject = Gson().fromJson(scan_result, JsonObject::class.java)
        val pubkey = json.get("pubkey")
        Log.d(km_tag, pubkey.asString)
        val onetimekey = json.get("onetimekey")
        Log.d(km_tag, onetimekey.asString)
        this.storeData(pubkey.asString, pubkey_file)
    }
}