package krypto.ciphers.block_ciphers

import krypto.utils.toBinaryStringRep
import krypto.utils.toUByteArray
import krypto.utils.toULong
import krypto.utils.xor
import kotlin.math.pow
import kotlin.random.Random
import kotlin.random.nextULong

/**
 * The implementation of the Data Encryption Standard
 *
 * DES is a block cipher which was published by FIPS in 1999 as a standard for encryption of electronic data.
 *
 * The standard can be found here: [https://csrc.nist.gov/CSRC/media/Publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf]
 *
 * @property key The key for the cipher (must be 8 bytes long)
 * @property subKeys The list containing the subkeys generated from the [key]
 * @property modes The list of accepted modes at the moment
 * @property mode The mode of operation as string (with uppercase letters)
 * @property iv The initialization vector. It's not used in all modes.
 * @property IP IP is used as the initial permutation during encryption and decryption
 * @property IPinv IPinv is used as the final permutation during encryption and decryption
 * @property E E is used to expand the part of the msg to the correct length when given to the Feistel function
 * @property P P is used as for permutation as the last step of the Feistel function
 * @property sBoxes The [sBoxes] are substitution boxes designed to transform the data
 * @property PC1 PC1 is used during the generation of the [subKeys]
 * @property PC2 PC2 is used during the generation of the [subKeys]
 * @property shifts The shifts array holds the number of shifts needed during the generation of the [subKeys]
 *
 * @constructor Creates a DES instance
 */
@OptIn(ExperimentalUnsignedTypes::class)
class DES(private val key: UByteArray, private val mode: String): BlockCipherInterface {

    /**
     * The list containing the subkeys generated from the [key]
     */
    private var subKeys: List<String>

    /**
     * The list of accepted modes at the moment
     */
    private val modes: List<String> = listOf("ECB", "CBC")

    /**
     * The initialization vector ([iv]) is not used in all modes.
     */
    var iv: UByteArray = Random.nextULong().toUByteArray()
    set(value) {
        require(value.size == 8) {"IV must be of size 8 bytes (64 bit)"}
        field = value
    }

    /**
     * [IP] is used as the initial permutation during encryption and decryption
     */
    private val IP = intArrayOf(
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    )

    /**
     * [IPinv] is used as the final permutation during encryption and decryption
     */
    private val IPinv = intArrayOf(
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    )

    /**
     * [E] is used to expand the part of the msg to the correct length when given to the Feistel function
     */
    private val E = intArrayOf(
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    )

    /**
     * [P] is used as for permutation as the last step of the Feistel function
     */
    private val P = intArrayOf(
        16,  7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
    )

    /**
     * The [sBoxes] are substitution boxes designed to transform the data
     */
    private val sBoxes = arrayOf(
        intArrayOf(
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
        intArrayOf(
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
        intArrayOf(
            10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
            13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
            13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
            1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12),
        intArrayOf(
            7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
            13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
            10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
            3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
        ),
        intArrayOf(
            2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
            14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
            4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
            11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3),
        intArrayOf(
            12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
            10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
            9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
            4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13),
        intArrayOf(
            4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
            13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
            1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
            6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12),
        intArrayOf(
            13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
            1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
            7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
            2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11))

    /**
     * [PC1] is used during the generation of the [subKeys]
     */
    private val PC1 = intArrayOf(
        57, 49, 41, 33, 25, 17,  9,
        1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    )

    /**
     * [PC2] is used during the generation of the [subKeys]
     */
    private val PC2 = intArrayOf(
        14, 17, 11, 24,  1,  5,
        3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    )

    /**
     * The [shifts] array holds the number of shifts needed during the generation of the subkeys
     */
    private val shifts = intArrayOf(
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    )
    
    init {
        require(key.size == 8) {"Size of the key must be 8 bytes (64 bit)"}
        require(modes.contains(mode)) {"Mode has to be part of $modes"}
        subKeys = generateSubKeys()
    }

    /**
     * This function generates the [subKeys] based on the [key]
     *
     * First the key is shortened and permuted to 56 bits with the help of [PC1].
     * Then based on the index of the given subkey the two half of this key is rotated mod 2^28 with the step given by [shifts].
     * Lastly the two halves are concatenated and permuted with the help of [PC2]]
     *
     * @return The subkeys as a list of string containing the bits(each string is 48 bits long)
     */
    internal fun generateSubKeys(): List<String> {
        val res = MutableList(16) { index ->
            val selectedBits = permutation(key.toBinaryStringRep(), PC1)
            var left = selectedBits.substring(0, 28)
            var right = selectedBits.substring(28)
            for (i in 0 until index+1) {
                left = rotateLeftWithGiven(left, shifts[i])
                right = rotateLeftWithGiven(right, shifts[i])
            }
            val new = permutation(left + right, PC2)
            new
        }.toList()
        return res
    }

    /**
     * Rotation mod 2^28 with a given amount of steps
     *
     * The number is represented as a string of 1-s and 0-s. First we convert it back to a 32-bit integer, then
     * apply shifting (which is between 1 or 2 steps) and mask the bits which should go at the back of the number.
     *
     * @param s The string containing the 28 bit long number
     * @param i The amount of rotating steps
     * @return The rotated number as a string of 1-s and 0-s
     */
    fun rotateLeftWithGiven(s: String, i: Int): String {
        var sInt = s.toUInt(2)
        sInt = sInt.rotateLeft(i)
        val sIntLast28 = sInt and 0xFFFFFFFu
        val shiftOverflowMask = 2.toDouble().pow(i.toDouble()).toUInt() - 1u shl 28
        val overflow = sInt and shiftOverflowMask
        val overflowShiftBack = overflow shr 28
        sInt = sIntLast28 or overflowShiftBack
        return sInt.toString(2).padStart(28, '0').takeLast(28)
    }

    /**
     * Encrypting a block
     *
     * This is the main method of DES. First we check whether the given block is long enough.
     * Then we use a permutation given by [IP] and split the block into two 32 bit long parts.
     * The main round of the encryption is the following:
     * 1. The right part is given to the Feistel function with the index of the current round
     * 2. The output of the Feistel functin is XOR-ed to the left part
     * 3. The right and left parts are swapped
     *
     * The main round is repeated 16 times.
     * Lastly the left and the right parts are concatenated and permuted with [IPinv]
     *
     * @param msg The block to be encrypted
     * @return The encrypted block
     */
    override fun encryptBlock(msg: UByteArray): UByteArray {
        require(msg.size == 8) {"Size of the message block must be 8 bytes (64 bit)"}

        var msgString = msg.toBinaryStringRep()
        msgString = permutation(msgString, IP)

        var left = msgString.substring(0, msgString.length / 2)
        var right = msgString.substring(msgString.length / 2, msgString.length)

        for (i in 0 until 16) {
            val temp = right
            right = feistelFunction(right, i)
            right = (left.toUInt(2) xor right.toUInt(2)).toString(2).padStart(32, '0')
            left = temp
        }

        msgString = right + left
        val result = permutation(msgString, IPinv)

        return result.toUByteArray()
    }

    /**
     * Decrypting a block
     *
     * The decryption in DES is similar to the encryption. The only difference is that the [subKeys] are used in
     * a reversed order. Therefore, before calling [encryptBlock] we reverse the [subKeys]. After the method call we
     * have to reorder the [subKeys] in the correct way.
     *
     * @param c The encrypted block
     * @return The decrypted block
     */
    override fun decryptBlock(c: UByteArray): UByteArray {
        subKeys = subKeys.reversed()
        val res = encryptBlock(c)
        subKeys = subKeys.reversed()
        return res

    }

    /**
     * The Feistel function
     *
     * The Feistel function first extends the 32 bit long right half of the msg to 48 bits with [E],
     * because the subkeys are 48 bits long. Then the extended right half is XOR-ed with the subkey given by [i].
     * The output of the operation is broken up into 6 bit long parts and these 6 bit long parts are used the
     * address the 8 S-Boxes given in [sBoxes]. These numbers are returned by calling [getOutputFromGivenSBox].
     * The numbers are collected (each is 4 bit long, so the total is 32 bit), concatenated and permuted with [P].
     *
     * @param right The right half of the block
     * @param i The index of the current round
     * @return The output of the F function
     */
    fun feistelFunction(right: String, i: Int): String {
        val extendedRight = extended(right)
        val subKey = subKeys[i]
        val substitutionInput = (extendedRight.toULong(2) xor subKey.toULong(2))
            .toString(2).padStart(48, '0').takeLast(48)
        val substitutionBlocks = substitutionInput.chunked(6)
        val sb = StringBuilder()
        substitutionBlocks.forEachIndexed { index, s ->
            sb.append(getOutputFromGivenSBox(s, index))
        }
        return permutation(sb.toString(), P)
    }

    /**
     * Get a specific value from an S-box
     *
     * The 6 bit long String of 1-s and 0-s is interpreted int the following way:
     * - The row index is the first char and the last concatenated.
     * - The middle 4 chars are the column index.
     *
     * @param s The string containing the row and a column index
     * @param index The index of the S-box to be used
     * @return The number as a binary string given by column and row in the given S-box
     */
    internal fun getOutputFromGivenSBox(s: String, index: Int): String {
        val row = (s.first().toString() + s.last().toString()).toInt(2)
        val column = s.substring(1, s.length-1).toInt(2)
        return sBoxes[index][row * 16 + column].toString(2).padStart(4, '0')
    }

    /**
     * Extends a 32 bit long String to be 48 bit long
     *
     * The extension is a permutation with the help of [E]
     *
     * @param right The 32 bit long String to be extended
     * @return The extended string
     */
    internal fun extended(right: String): String {
        return permutation(right, E)
    }

    /**
     * Creates a permutation from a string with a given permutation
     *
     * The array given as the second parameter holds the new order of indexes.
     *
     * @param msgString The string input
     * @param p The array holding the order of the index in the permutation
     * @return The string created by the permutation given by [p]
     */
    fun permutation(msgString: String, p: IntArray): String {
        val charSeq = CharArray(p.size) { index ->
            msgString[p[index]-1]
        }
        return charSeq.concatToString()
    }

    /**
     * Encrypts a msg
     *
     * The length of [msg] has to be a multiple of the block size, therefore the msg has to be padded.
     * If the msg is multiple of the block size then it is padded anyway with a whole block to avoid confusion on
     * the decryption side.
     *
     * The method of encrypting each block depends on the mode of operation given in [mode]. The detailed description
     * of these modes can be found here: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
     *
     * @param msg The msg to be encrypted as a [UByteArray]
     * @return The encrypted msg
     */
    override fun encrypt(msg: UByteArray): UByteArray {
        val paddedMsg: UByteArray = pad(msg.toMutableList())
        if (mode == "ECB") {
            return paddedMsg.toList().chunked(8).flatMap {
                encryptBlock(it.toUByteArray())
            }.toUByteArray()
        }
        if (mode == "CBC") {
            val blocks = paddedMsg.toList().chunked(8).toMutableList()
            val c : MutableList<List<UByte>> = mutableListOf(iv.toList())
            blocks.forEachIndexed { index, uBytes ->
                val encryptInputBlock = c[index].toUByteArray() xor uBytes.toUByteArray()
                val encryptedBlock = encryptBlock(encryptInputBlock)
                c.add(encryptedBlock.toList())
            }
            return c.slice(1 .. blocks.size).flatten().toUByteArray()
        }
        throw IllegalStateException("Mode is incorrect")
    }

    /**
     * Padding the msg to a multiple of the block size based on ISO-7816
     *
     * @param msg The msg to be padded
     * @return The padded msg
     */
    internal fun pad(msg: MutableList<UByte>): UByteArray {
        // Adding 0x80 as the first byte of the padding
        msg.add(0x80u)
        // Make the length of the msg multiple of the block size with 0 bytes
        while(msg.size % 8 != 0) {
            msg.add(0u)
        }
        return msg.toUByteArray()
    }

    /**
     * Remove the padding from the msg. The padding is believed to be ISO-7816
     *
     * @param msg The padded msg
     * @return The msg with padding removed
     */
    internal fun removePadding(msg: MutableList<UByte>): UByteArray {
        // Removing the 0 bytes from the end of the list
        while (msg.last() == 0u.toUByte()) {
            msg.removeLast()
        }
        // After the 0 bytes we have to remove the 0x80 byte, the last part of the padding
        if (msg.last() != 0x80u.toUByte()) {
            throw IllegalStateException("The padding is wrong")
        } else {
            msg.removeLast()
        }
        return msg.toUByteArray()
    }

    /**
     * Decrypting a msg
     *
     * The method of decrypting each block depends on the mode of operation given in [mode]. The detailed description
     * of these modes can be found here: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
     *
     * The padding has to be removed from the decrypted msg at the end.
     *
     * @param c The encrypted msg
     * @return The decrypted msg
     */
    override fun decrypt(c: UByteArray): UByteArray {
        if (mode == "ECB") {
            val plaintext = c.toList().chunked(8).flatMap {
                decryptBlock(it.toUByteArray())
            }.toMutableList()
            return removePadding(plaintext)
        }
        if (mode == "CBC") {
            val blocks = c.toList().chunked(8).toMutableList()
            val blocksToXor = mutableListOf(iv.toList())
            blocksToXor.addAll(blocks)
            val msg = mutableListOf(iv.toList())
            blocks.forEachIndexed { index, uBytes ->
                val interBlock = decryptBlock(uBytes.toUByteArray())
                val decryptedInputBlock = blocksToXor[index].toUByteArray() xor interBlock.toUByteArray()
                msg.add(decryptedInputBlock.toList())
            }
            return removePadding(msg.slice(1 .. blocks.size).flatten().toMutableList())
        }
        return ubyteArrayOf()
    }
}