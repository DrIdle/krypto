package krypto.hash

import krypto.utils.toUByteArray
import krypto.utils.toUInt

/**
 * This class implements the SHA-1 hash function
 *
 * The SHA-1 algorithm was published in RFC-3174 (https://www.rfc-editor.org/rfc/rfc3174.html)
 * Although the algorithm is considered unsafe, it's still widely used as a message digest algorithm.
 *
 * @property h0 Constant used by SHA1
 * @property h1 Constant used by SHA1
 * @property h2 Constant used by SHA1
 * @property h3 Constant used by SHA1
 * @property h4 Constant used by SHA1
 */
@OptIn(ExperimentalUnsignedTypes::class)
open class SHA1: HashInterface {

    /**
     * Constants used by SHA1
     */
    private var h0: UInt = 0x67452301u
    private var h1: UInt = 0xEFCDAB89u
    private var h2: UInt = 0x98BADCFEu
    private var h3: UInt = 0x10325476u
    private var h4: UInt = 0xC3D2E1F0u

    /**
     * This function gives back the value of k based on the given iteration number
     *
     * @param t The current iteration number in the main loop
     * @return The value for this iteration
     */
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

    /**
     * Gives back the block size for this hash function
     *
     * @return The block size
     */
    override fun blockSize(): Int {
        return 64
    }

    /**
     * Gives back the digest size for this hash function
     *
     * @return The digest size
     */
    override fun digestSize(): Int {
        return 20
    }

    /**
     * Calculates the output of the f function based on the value of [b], [c], [d] and the given iteration number
     *
     * @param b The value of b
     * @param c The value of c
     * @param d The value of d
     * @param i The iteration number in the main loop
     */
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

    /**
     * Computes the hash of given data
     *
     * First the data must be padded so its length is congruent 448 mod 512 (first 0x80 is padded, then 0 bytes)
     * Next, we concat the length of the original data (without padding) as a 64-bit long integer with the help
     * of [concatOriginalLength]. Then we calculate the digest of [m] with the [digestGeneration] method and return
     * the digest as a [UByteArray]
     *
     * @param m The date to be hashed
     * @return The hash as [UByteArray]
     */
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


        return hashValue.flatMap { uIntElement ->
            uIntElement.toUByteArray()
        }.toUByteArray()
    }

    /**
     * Gives back and instance of the class
     */
    override fun getInstance(): HashInterface {
        return SHA1()
    }

    /**
     * Concatenate the [originalLength] to the message as a 64-bit long integer
     *
     * @param originalLength The length of original message in bytes
     * @param msgCopy The copy of the msg as a [MutableList]
     */
    open fun concatOriginalLength(originalLength: ULong, msgCopy: MutableList<UByte>) {
        msgCopy.addAll((originalLength * 8u).toUByteArray())
    }

    /**
     * This function generates the digest of the msg
     *
     * First the msg is sliced into parts of 512 bit length. For each of these groups, we create 16 32-bit long integers.
     * The next step is to extend this collection into a new one with length 80.
     * Then we initialize the variables a, b, c, d and e with [h0], [h1], [h2], [h3] and [h4]. After this we run a
     * for loop for 80 iteration and update these variables. After the last iteration we add the values of a, b, c, d
     * and e to [h0], [h1], [h2], [h3], [h4] and do this for the next 512 bit long group.
     *
     * After the last group the digest consists of [h0], [h1], [h2], [h3] and [h4] written next to each other.
     *
     * @param msgCopy The message whose digest is calculated
     * @return The digest as a [UIntArray]
     */
    open fun digestGeneration(msgCopy: MutableList<UByte>): UIntArray {
        val chunks = msgCopy.chunked(64)
        chunks.forEach { uByteList ->
            val uByteArrays = uByteList.chunked(4)
            val uintArray = UIntArray(80)
            uByteArrays.forEachIndexed { index, uBytes ->
                uintArray[index] = uBytes.toUByteArray().toUInt()
            }
            val uintArrayList = uintArray.toMutableList()
            // Populating the array to hold 80 element
            for (i in 16..79) {
                uintArrayList[i] =
                    (uintArrayList[i - 3] xor uintArrayList[i - 8] xor uintArrayList[i - 14] xor uintArrayList[i - 16]).rotateLeft(
                        1
                    )
            }
            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4

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

            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
        }
        return uintArrayOf(h0, h1, h2, h3, h4)
    }
}