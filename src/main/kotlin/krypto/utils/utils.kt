package krypto.utils

import java.nio.charset.Charset
import kotlin.experimental.xor

/**
 * A function to XOR two string using a charset
 *
 * @param key The other string in the XOR operation
 * @param charset The charset to be used during the conversion to bytes
 * @return The result of the XOR operation
 */
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

/**
 * Convert a string of 1s and 0s to a [UByteArray]
 *
 * The length of the string must be a multiple of 8, so we can treat them as bytes.
 * We split the string into parts with length 8 and make a byte out of the 1s and 0s.
 *
 * @return The [UByteArray] from the string
 */
@OptIn(ExperimentalUnsignedTypes::class)
fun String.toUByteArray(): UByteArray {
    if (this.length % 8 != 0) {
        throw Exception("The size of the string must be a multiple of 8")
    }
    return this.chunked(8).map {
        it.toUByte(2)
    }.toUByteArray()
}

/**
 * Converts a [UInt] into a [UByteArray]
 *
 * We split the [UInt] into bytes with shifting and concatenate them to from a [UByteArray]
 *
 * @return The [UByteArray] we got from the [UInt]
 */
@OptIn(ExperimentalUnsignedTypes::class)
fun UInt.toUByteArray(): UByteArray {
    return ubyteArrayOf(shr(24).toUByte(), shr(16).toUByte(), shr(8).toUByte(),this.toUByte())
}

/**
 * Converts a [ULong] into a [UByteArray]
 *
 * We split the [ULong] into bytes with shifting and concatenate them to from a [UByteArray]
 *
 * @return The [UByteArray] we got from the [ULong]
 */
@OptIn(ExperimentalUnsignedTypes::class)
fun ULong.toUByteArray(): UByteArray {
    return  ubyteArrayOf(shr(56).toUByte(), shr(48).toUByte(), shr(40).toUByte(), shr(32).toUByte(), shr(24).toUByte(), shr(16).toUByte(), shr(8).toUByte(), this.toUByte())
}

/**
 * Convert a [UByteArray] holding 4 bytes to a [UInt] in little endian representation.
 *
 * @return The [UInt] we got from the [UByteArray] in little endian
 */
@OptIn(ExperimentalUnsignedTypes::class)
fun UByteArray.littleEndian(): UInt {
    if (this.size != 4) {
        throw Exception("ByteArray must be of size 4")
    }
    return this[0] + (this[1].toUInt() shl 8) + (this[2].toUInt() shl 16) + (this[3].toUInt() shl 24)

}

/**
 * Make a string of 1s and 0s from a [UByteArray]
 *
 * @return A binary string representing the [UByteArray]
 */
@OptIn(ExperimentalUnsignedTypes::class)
fun UByteArray.toBinaryStringRep(): String {
    val sb = StringBuilder()
    this.forEach {
        sb.append(it.toString(2).padStart(8, '0'))
    }
    return sb.toString()
}

/**
 * Make a string of the hexadecimal representation of the [UByteArray]
 *
 * @return The hexadecimal string we got from the [UByteArray]
 */
@OptIn(ExperimentalUnsignedTypes::class)
fun UByteArray.hexdigest(): String {
    val sb = StringBuilder()
    this.forEach {
        sb.append(it.toString(16).padStart(2, '0'))
    }
    return sb.toString()
}

/**
 * Convert a [UInt] in little endian to a [UByteArray] in big endian
 *
 * @return The [UByteArray] representing the [UInt] in big endian
 */
@OptIn(ExperimentalUnsignedTypes::class)
fun UInt.revLittleEndian(): UByteArray {
    return ubyteArrayOf(this.toUByte(), (this shr 8).toUByte(), (this shr 16).toUByte(), (this shr 24).toUByte())
}

/**
 * Convert a [UByteArray] with size less or equal to 4 to a [UInt]
 *
 * @return The [UInt] from the [UByteArray]
 */
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

/**
 * Convert a [UByteArray] with size less or equal to 8 to a [ULong]
 *
 * @return The [ULong] from the [UByteArray]
 */
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

/**
 * Infix function to make elementwise XOR-ing to same sized [UByteArray]s easier.
 *
 * @param other The [UByteArray] to which should be XOR to this elementwise
 * @return The [UByteArray] containing the result of the elementwise XOR
 */
@OptIn(ExperimentalUnsignedTypes::class)
infix fun UByteArray.xor(other: UByteArray): UByteArray {
    require(this.size == other.size) {"The arrays must be the same length"}

    return this.zip(other) { thisByte, otherByte ->
        thisByte xor otherByte
    }.toUByteArray()
}