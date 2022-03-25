package krypto.utils

import java.nio.charset.Charset
import kotlin.experimental.xor

fun String.strxor(key:String, charset: Charset): String {
    if (key.length != this.length) {
        throw IllegalArgumentException("The key must be of the same length as the string")
    }

    val thisAsByteArray: ByteArray = this.toByteArray(charset = charset)
    val keyAsByteArray: ByteArray = key.toByteArray(charset = charset)

    val resultByteArray: ByteArray = thisAsByteArray.zip(keyAsByteArray) {
        infoByte, keyByte ->
        infoByte xor keyByte
    }.toByteArray()

    return resultByteArray.toString(charset = charset)
}

fun ByteArray.toInt(): Int {
    var newArray: ByteArray
    if (this.size != 4) {
        //throw Exception("ByteArray must be of size 4")
        newArray = ByteArray(4)
        this.copyInto(destination = newArray, destinationOffset = (4 - this.size))
    } else {
        newArray = this
    }
    var result = 0
    for (i in newArray.indices) {
        result = result or (newArray[i].toInt() shl 8 * ((newArray.size - 1)-i))
    }
    return result
}