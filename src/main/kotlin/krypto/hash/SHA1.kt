package krypto.hash

import krypto.utils.toUByteArray
import krypto.utils.toUInt

@OptIn(ExperimentalUnsignedTypes::class)
open class SHA1: AbstractHash() {

    // Constants used by SHA1
    private var H0: UInt = 0x67452301u
    private var H1: UInt = 0xEFCDAB89u
    private var H2: UInt = 0x98BADCFEu
    private var H3: UInt = 0x10325476u
    private var H4: UInt = 0xC3D2E1F0u

    open fun k(t: Int): UInt {
        return when(t) {
            in 0..19 -> 0x5A827999u
            in 20..39 -> 0x6ED9EBA1u
            in 40..59 -> 0x8F1BBCDCu
            in 60..79 -> 0xCA62C1D6u
            else -> {
                throw RuntimeException("Bad t provided")
            }
        }
    }

    override fun blockSize(): Int {
        return 64
    }

    override fun digestSize(): Int {
        return 20
    }

    open fun f(b: UInt, c: UInt, d: UInt, i: Int): UInt {
        return when(i) {
            in 0..19 -> (b and c) or (b.inv() and d)
            in 20..39 -> b xor c xor d
            in 40..59 -> (b and c) or (b and d) or (c and d)
            in 60..79 -> b xor c xor d
            else -> {
                throw RuntimeException("Bad i provided")
            }
        }
    }

    override fun hash(m: UByteArray): UByteArray {
        val originalLength = m.size.toULong()

        // Padding
        val msgCopy = m.copyOf().toMutableList()
        msgCopy.add(0x80.toUByte())

        var starter = originalLength * 8u + 8u
        val target: ULong = 448u
        while ((starter % 512u) != target) {
                msgCopy.add(0x0.toUByte())
                starter += 8u
        }

        concatOriginalLength(originalLength, msgCopy)

        val hashValue = digestGeneration(msgCopy)


        return hashValue.map { uIntElement ->
            uIntElement.toUByteArray()
        }.flatten().toUByteArray()
    }

    open fun concatOriginalLength(originalLength: ULong, msgCopy: MutableList<UByte>) {
        // Concat length of the message
        val originalLengthLeft = ((originalLength * 8u) shr 32).toUInt().toUByteArray()
        val originalLengthRight = (((originalLength * 8u) shl 32) shr 32).toUInt().toUByteArray()

        msgCopy.addAll(originalLengthLeft + originalLengthRight)
    }

    open fun digestGeneration(msgCopy: MutableList<UByte>): UIntArray {
        val chunks = msgCopy.chunked(64)
        chunks.forEach { uByteList ->
            val uByteArrays = uByteList.chunked(4)
            val uintArray = UIntArray(80)
            uByteArrays.forEachIndexed { index, uBytes ->
                uintArray[index] = uBytes.toUByteArray().toUInt()
            }
            val uintArrayList = uintArray.toMutableList()
            for (i in 16..79) {
                uintArrayList[i] =
                    (uintArrayList[i - 3] xor uintArrayList[i - 8] xor uintArrayList[i - 14] xor uintArrayList[i - 16]).rotateLeft(
                        1
                    )
            }
            var a = H0
            var b = H1
            var c = H2
            var d = H3
            var e = H4

            for (i in 0..79) {
                val f: UInt = f(b, c, d, i)
                val k: UInt = k(i)
                val temp = a.rotateLeft(5) + f + e + k + uintArrayList[i]
                e = d
                d = c
                c = b.rotateLeft(30)
                b = a
                a = temp
            }

            H0 += a
            H1 += b
            H2 += c
            H3 += d
            H4 += e
        }
        return uintArrayOf(H0, H1, H2, H3, H4)
    }
}