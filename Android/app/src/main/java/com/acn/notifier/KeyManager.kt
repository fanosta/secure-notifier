package com.acn.notifier

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
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
}