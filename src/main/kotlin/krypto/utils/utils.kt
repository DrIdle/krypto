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
    val newArray: ByteArray
    //TODO: limit the size of the array to be smaller or equal to 4
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

@OptIn(ExperimentalUnsignedTypes::class)
fun UInt.toUByteArray(): UByteArray {
    return ubyteArrayOf(shr(24).toUByte(), shr(16).toUByte(), shr(8).toUByte(),this.toUByte())
}

@OptIn(ExperimentalUnsignedTypes::class)
fun UByteArray.toUInt(): UInt {
    val newArray: UByteArray
    //TODO: limit the size of the array to be smaller or equal to 4
    if (this.size != 4) {
        //throw Exception("ByteArray must be of size 4")
        newArray = UByteArray(4)
        this.copyInto(destination = newArray, destinationOffset = (4 - this.size))
    } else {
        newArray = this
    }
    var result: UInt = 0u
    for (i in newArray.indices) {
        result = result or (newArray[i].toUInt() shl 8 * ((newArray.size - 1)-i))
    }
    return result
}