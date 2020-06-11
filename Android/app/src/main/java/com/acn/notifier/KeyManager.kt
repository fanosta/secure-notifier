package com.acn.notifier

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class KeyManager(mainActivity: MainActivity) {

    val km_tag = "KeyManager"
    val key_name = "file_key"
    val ks: KeyStore
    var key_file: File? = null
    var iv: ByteArray? = null

    init {
        val context = mainActivity.applicationContext
        val path = context.getFilesDir()
        val keyDirectory = File(path, "key")
        keyDirectory.mkdirs()

        key_file = File(keyDirectory, "key.txt")

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

    private fun writeToFile(encrypted_data: String) {
        val enc_iv = Base64.encodeToString(iv, Base64.DEFAULT)
        val write_to_file = enc_iv.plus(encrypted_data)

        FileOutputStream(key_file).use {
            it.write(write_to_file.toByteArray())
        }
    }

    private fun readFromFile(): String {
        val read_from_file = FileInputStream(key_file).bufferedReader().use {
            it.readText()
        }

        val split = read_from_file.split("\n")
        iv = Base64.decode(split.get(0).toByteArray(), Base64.DEFAULT)

        return split.get(1)
    }

    fun storeData(data: String) {
        Log.d(km_tag, "storeData")
        val encrypted_data = encryptData(data)
        writeToFile(encrypted_data)
    }

    fun loadData(): String {
        Log.d(km_tag, "loadData")
        val encrypted_data = readFromFile()
        return decryptData(encrypted_data)
    }

    // TODO: replace with real SenderToken
    fun getSenderToken(): PublicKey{
        val key_pair: KeyPair = generateECDHKeyPair()

        return key_pair.getPublic()
    }

    fun generateECDHKeyPair(): KeyPair {
        val curve_25519: X9ECParameters = CustomNamedCurves.getByName("Curve25519")
        val ec_spec = ECParameterSpec(
            curve_25519.getCurve(),
            curve_25519.getG(),
            curve_25519.getN(),
            curve_25519.getH(),
            curve_25519.getSeed()
        )

        val key_pair_generator: KeyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider())
        key_pair_generator.initialize(ec_spec)

        val key_pair: KeyPair = key_pair_generator.generateKeyPair()

        return key_pair
    }

    fun getSharedSecret(public_key: PublicKey, private_key: PrivateKey): ByteArray {
        val key_agreement: KeyAgreement = KeyAgreement.getInstance("ECDH", BouncyCastleProvider())
        key_agreement.init(private_key)
        key_agreement.doPhase(public_key, true)

        return key_agreement.generateSecret()
    }

    fun keyAgreement(): ByteArray {
        // get token id + public key
        val server_public_key: PublicKey = getSenderToken()

        val key_pair: KeyPair = generateECDHKeyPair()
        // send client_public_key to server
        val client_public_key: PublicKey = key_pair.getPublic()
        val client_private_key: PrivateKey = key_pair.getPrivate()
        // encrypt message with shared key
        val shared_key = getSharedSecret(server_public_key, client_private_key)

        return shared_key
    }
}