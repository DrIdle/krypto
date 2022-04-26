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

@OptIn(ExperimentalUnsignedTypes::class)
fun String.toUByteArray(): UByteArray {
    if (this.length % 8 != 0) {
        throw Exception("The size of the string must be a multiple of 8")
    }
    return this.chunked(8).map {
        it.toUByte(2)
    }.toUByteArray()
}

fun ByteArray.toInt(): Int {
    val newArray: ByteArray
    if (this.size > 4) {
        throw Exception("ByteArray must be of max size 4")
    } else {
        newArray = ByteArray(4)
        this.copyInto(destination = newArray, destinationOffset = (4 - this.size))
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
fun ULong.toUByteArray(): UByteArray {
    return  ubyteArrayOf(shr(56).toUByte(), shr(48).toUByte(), shr(40).toUByte(), shr(32).toUByte(), shr(24).toUByte(), shr(16).toUByte(), shr(8).toUByte(), this.toUByte())
}

@OptIn(ExperimentalUnsignedTypes::class)
fun UByteArray.littleEndian(): UInt {
    if (this.size != 4) {
        throw Exception("ByteArray must be of size 4")
    }
    return this[0] + (this[1].toUInt() shl 8) + (this[2].toUInt() shl 16) + (this[3].toUInt() shl 24)

}

@OptIn(ExperimentalUnsignedTypes::class)
fun UByteArray.toBinaryStringRep(): String {
    val sb = StringBuilder()
    this.forEach {
        sb.append(it.toString(2).padStart(8, '0'))
    }
    return sb.toString()
}

@OptIn(ExperimentalUnsignedTypes::class)
fun UInt.revLittleEndian(): UByteArray {
    return ubyteArrayOf(this.toUByte(), (this shr 8).toUByte(), (this shr 16).toUByte(), (this shr 24).toUByte())
}

@OptIn(ExperimentalUnsignedTypes::class)
fun UByteArray.toUInt(): UInt {
    val newArray: UByteArray
    if (this.size > 4) {
        throw Exception("ByteArray must be of max size 4")
    } else {
        newArray = UByteArray(4)
        this.copyInto(destination = newArray, destinationOffset = (4 - this.size))
    }
    var result: UInt = 0u
    for (i in newArray.indices) {
        result = result or (newArray[i].toUInt() shl 8 * ((newArray.size - 1)-i))
    }
    return result
}

@OptIn(ExperimentalUnsignedTypes::class)
fun UByteArray.toULong(): ULong {
    val newArray: UByteArray
    if (this.size > 8) {
        throw Exception("ByteArray must be of max size 8")
    } else {
        newArray = UByteArray(8)
        this.copyInto(destination = newArray, destinationOffset = (8 - this.size))
    }
    var result: ULong = 0u
    for (i in newArray.indices) {
        result = result or (newArray[i].toULong() shl 8 * ((newArray.size - 1)-i))
    }
    return result
}