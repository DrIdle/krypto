package krypto.ciphers.stream_ciphers

import krypto.utils.littleEndian
import krypto.utils.revLittleEndian
import krypto.utils.toUByteArray
import kotlin.random.Random

@OptIn(ExperimentalUnsignedTypes::class)
class Salsa20 constructor(private var key: UByteArray, var nonce: ULong?) {

    private val sigma = arrayOf(
        ubyteArrayOf(101u, 120u, 112u, 97u),
        ubyteArrayOf(110u, 100u, 32u, 51u),
        ubyteArrayOf(50u, 45u, 98u, 121u),
        ubyteArrayOf(116u, 101u, 32u, 107u)
    )

    private val tau = arrayOf(
        ubyteArrayOf(101u, 120u, 112u, 97u),
        ubyteArrayOf(110u, 100u, 32u, 49u),
        ubyteArrayOf(54u, 45u, 98u, 121u),
        ubyteArrayOf(116u, 101u, 32u, 107u)
    )

    init {
        if (!((key.size == 32) or (key.size == 16))) {
            throw IllegalArgumentException("Key size must be 256 bit (32 byte) or 128 bit (16 byte)")
        }
    }

    fun quarterRound(y: UIntArray): UIntArray {
        val z = UIntArray(4)
        z[1] = y[1] xor (y[0] + y[3]).rotateLeft(7)
        z[2] = y[2] xor (z[1] + y[0]).rotateLeft(9)
        z[3] = y[3] xor (z[2] + z[1]).rotateLeft(13)
        z[0] = y[0] xor (z[3] + z[2]).rotateLeft(18)

        return z
    }

    fun rowRound(y: UIntArray): UIntArray {
        val z = UIntArray(16)

        val qrResult1 = quarterRound(uintArrayOf(y[0], y[1], y[2], y[3]))
        val qrResult2 = quarterRound(uintArrayOf(y[5], y[6], y[7], y[4]))
        val qrResult3 = quarterRound(uintArrayOf(y[10], y[11], y[8], y[9]))
        val qrResult4 = quarterRound(uintArrayOf(y[15], y[12], y[13], y[14]))

        z[0] = qrResult1[0]
        z[1] = qrResult1[1]
        z[2] = qrResult1[2]
        z[3] = qrResult1[3]

        z[5] = qrResult2[0]
        z[6] = qrResult2[1]
        z[7] = qrResult2[2]
        z[4] = qrResult2[3]

        z[10] = qrResult3[0]
        z[11] = qrResult3[1]
        z[8] = qrResult3[2]
        z[9] = qrResult3[3]

        z[15] = qrResult4[0]
        z[12] = qrResult4[1]
        z[13] = qrResult4[2]
        z[14] = qrResult4[3]

        return z
    }

    fun columnRound(x: UIntArray): UIntArray {
        val y = UIntArray(16)

        val qrResult1 = quarterRound(uintArrayOf(x[0], x[4], x[8], x[12]))
        val qrResult2 = quarterRound(uintArrayOf(x[5], x[9], x[13], x[1]))
        val qrResult3 = quarterRound(uintArrayOf(x[10], x[14], x[2], x[6]))
        val qrResult4 = quarterRound(uintArrayOf(x[15], x[3], x[7], x[11]))

        y[0] = qrResult1[0]
        y[4] = qrResult1[1]
        y[8] = qrResult1[2]
        y[12] = qrResult1[3]

        y[5] = qrResult2[0]
        y[9] = qrResult2[1]
        y[13] = qrResult2[2]
        y[1] = qrResult2[3]

        y[10] = qrResult3[0]
        y[14] = qrResult3[1]
        y[2] = qrResult3[2]
        y[6] = qrResult3[3]

        y[15] = qrResult4[0]
        y[3] = qrResult4[1]
        y[7] = qrResult4[2]
        y[11] = qrResult4[3]

        return y
    }

    fun doubleRound(x: UIntArray): UIntArray {
        return rowRound(columnRound(x))
    }

    fun salsa20Hash(x: UByteArray): UByteArray {
        var xAsWords = UIntArray(16)

        for (i in 0 until 16) {
            xAsWords[i] = x.copyOfRange(i*4, (i*4)+4).littleEndian()
        }

        val xAsWordsOriginal = xAsWords.copyOf()

        for (i in 0 until 10) {
            xAsWords = doubleRound(xAsWords)
        }

        val res = xAsWords.zip(xAsWordsOriginal) {
            xWord, zWord ->
            xWord + zWord
        }.toUIntArray().map {
            it.revLittleEndian()
        }.flatten().toUByteArray()

        return res
    }

    fun salsa20Expansion(k: UByteArray, n: UByteArray): UByteArray {
        if (k.size == 32) {
            return salsa20Hash(sigma[0] + k.copyOfRange(0,16) + sigma[1] + n + sigma[2] + k.copyOfRange(16,32)+ sigma[3])
        }
        if (k.size == 16) {
            return salsa20Hash(tau[0] + k + tau[1] + n + tau[2] + k + tau[3])
        }
        return ubyteArrayOf()
    }

    fun encodeDecode(m: UByteArray, counter: ULong = 0u): UByteArray {
        nonce = nonce ?: 0u
        val numberOfRounds = m.size / 64
        val result = UByteArray(m.size)
        var runningCounter = counter

        var keyStream: UByteArray = ubyteArrayOf()

        for (i in m.indices) {
            if (i % 64 == 0) {
                if (i!=0) {
                    runningCounter += 1u
                }
                keyStream = salsa20Expansion(key, nonce!!.toUByteArray()+runningCounter.toUByteArray().reversedArray())
            }
            result[i] = m[i] xor keyStream[i % 64]
        }
        return result
    }

}