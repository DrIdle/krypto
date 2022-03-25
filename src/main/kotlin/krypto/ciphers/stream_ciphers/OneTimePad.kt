package krypto.ciphers.stream_ciphers

import kotlin.experimental.xor

class OneTimePad {

    fun encodeAndDecode(informationByteArray: ByteArray, keyByteArray: ByteArray): ByteArray {
        if (informationByteArray.size != keyByteArray.size) {
            throw IllegalArgumentException("THe key must be as long as the information to be encoded")
        }
        return informationByteArray.zip(keyByteArray) {
            informationElement, keyElement ->
                informationElement xor keyElement
        }.toByteArray()
    }
}