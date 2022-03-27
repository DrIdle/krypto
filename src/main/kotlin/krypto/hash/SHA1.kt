package krypto.hash

import krypto.utils.toUByteArray
import krypto.utils.toUInt

class SHA1 {

    // Constants used by SHA1
    var H0: UInt = 0x67452301u
    var H1: UInt = 0xEFCDAB89u
    var H2: UInt = 0x98BADCFEu
    var H3: UInt = 0x10325476u
    var H4: UInt = 0xC3D2E1F0u

    private fun k(t: Int): UInt {
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

    @OptIn(ExperimentalUnsignedTypes::class)
    fun hash(msg: UByteArray): String {
        val originalLength = msg.size.toULong()

        // Padding
        val msgCopy = msg.copyOf().toMutableList()
        msgCopy.add(0x80.toUByte())

        var starter = originalLength * 8u + 8u
        val target: ULong = 448u
        while ((starter % 512u) != target) {
                msgCopy.add(0x0.toUByte())
                starter += 8u
        }

        // Concat length of the message
        val originalLengthLeft = (originalLength shr 32).toUInt().toUByteArray()
        val originalLengthRight = ((originalLength shl 32) shr 32).toUInt().toUByteArray()

        msgCopy.addAll(originalLengthRight)
        msgCopy.addAll(originalLengthLeft)

        val chunks = msgCopy.chunked(64)
        chunks.forEach { uByteList ->
            val uByteArrays = uByteList.chunked(4)
            val uintArray = UIntArray(80)
            uByteArrays.forEachIndexed { index, uBytes ->
                uintArray[index] = uBytes.toUByteArray().toUInt()
            }
            val uintArrayList = uintArray.toMutableList()
            for (i in 16..79) {
                uintArrayList[i] = (uintArrayList[i-3] xor uintArrayList[i-8] xor uintArrayList[i-14] xor uintArrayList[i-16]).rotateLeft(1)
            }
            var a = H0
            var b = H1
            var c = H2
            var d = H3
            var e = H4

            var f: UInt = 0U
            var k: UInt = 0U
            for (i in 0..79) {
                if (i in 0..19) {
                    f = (b and c) or (b.inv() and d)
                }
                if (i in 20..39){
                    f = b xor c xor d
                }
                if (i in 40..59) {
                    f = (b and c) or (b and d) or (c and d)
                }
                if (i in 60..79) {
                    f = b xor c xor d
                }
                k = k(i)
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
        val hashValue = uintArrayOf(H0, H1, H2, H3, H4)

        val hexDigest = StringBuilder()
        hashValue.map { uIntElement ->
            val uByteArray = uIntElement.toUByteArray()
            uByteArray.forEach { uByte ->
                hexDigest.append(uByte.toString(16).padStart(2, '0'))
            }
        }

        return hexDigest.toString()
    }
}