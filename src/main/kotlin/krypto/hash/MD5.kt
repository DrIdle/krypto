package krypto.hash

import krypto.utils.toUByteArray
import krypto.utils.toUInt
import kotlin.math.abs
import kotlin.math.sin

@OptIn(ExperimentalUnsignedTypes::class)
class MD5: SHA1() {

    private var a0: UInt = 0x67452301u
    //private var h0: UInt = 0x01234567u
    private var b0: UInt = 0xefcdab89u
    //private var h1: UInt = 0x89abcdefu
    private var c0: UInt = 0x98badcfeu
    //private var h2: UInt = 0xfedcba98u
    private var d0: UInt = 0x10325476u
    //private var h3: UInt = 0x76543210u

    private var s: IntArray = intArrayOf(
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21)

    private var k: UIntArray = uintArrayOf(
        0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
        0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
        0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
        0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
        0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
        0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
        0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
        0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
        0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
        0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
        0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
        0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
        0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
        0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
        0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
        0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u)

    override fun digestSize(): Int {
        return 16
    }

    override fun k(t: Int): UInt {
        return k[t]
    }

    override fun f(b: UInt, c: UInt, d: UInt, i: Int): UInt {
        return when(i) {
            in 0..15 -> (b and c) or (b.inv() and d)
            in 16..31 -> (d and b) or (d.inv() and c)
            in 32..47 -> b xor c xor d
            in 48..63 -> c xor (b or d.inv())
            else -> {
                throw RuntimeException("Bad i provided")
            }
        }
    }

    fun g(i: Int): Int {
        return when(i) {
            in 0..15 -> i
            in 16..31 -> ((5 * i) + 1) % 16
            in 32..47 -> ((3 * i) + 5) % 16
            in 48..63 -> (7 * i) % 16
            else -> {
                throw RuntimeException("Bad i provided")
            }
        }
    }

    override fun concatOriginalLength(originalLength: ULong, msgCopy: MutableList<UByte>) {
        // Concat length of the message
        val originalLengthLeft = ((originalLength * 8u) shr 32).toUInt().toUByteArray()
        val originalLengthRight = (((originalLength * 8u) shl 32) shr 32).toUInt().toUByteArray()

        val wholeNumber = originalLengthRight + originalLengthLeft
        msgCopy.addAll(wholeNumber)
    }

    override fun digestGeneration(msgCopy: MutableList<UByte>): UIntArray {
        val chunks = msgCopy.chunked(64)
        chunks.forEach { uByteList ->

            val m = uByteList.chunked(4).mapIndexed { index, uBytes ->
                if( index < 14) {
                    uBytes.toUByteArray().reversedArray().toUInt()
                } else {
                    uBytes.toUByteArray().toUInt()
                }
            }.toUIntArray()

            var a = a0
            var b = b0
            var c = c0
            var d = d0

            for (i in 0..63) {
                val f: UInt = f(b, c, d, i)
                val g: Int = g(i)

                val temp = b + (f + a + k(i) + m[g]).rotateLeft(s[i])

                a = d
                d = c
                c = b
                b = temp
            }

            a0 += a
            b0 += b
            c0 += c
            d0 += d
        }

        var res = uintArrayOf(a0, b0, c0, d0)

        res = res.map {
            it.toUByteArray().reversedArray().toUInt()
        }.toUIntArray()

        return res
    }

    override fun getInstance(): AbstractHash {
        return MD5()
    }
}