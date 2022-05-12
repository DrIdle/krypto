package krypto.mac

import krypto.hash.HashInterface
import krypto.utils.xor

/**
 * This class implements the HMAC algorithm
 *
 * The HMAC is MAC algorithm, which used a key and a hash function to generate the MAC of a given msg.
 * The detailed description of the algorithm can be found here: https://en.wikipedia.org/wiki/HMAC
 *
 * @property key The key to used during the MAC generation
 * @property digest The hash function to be used during the MAC generation
 */
@OptIn(ExperimentalUnsignedTypes::class)
class HMAC<T: HashInterface>(private val key: UByteArray, private val digest: T): MACInterface {

    /**
     * Generating the MAC of the msg
     *
     * The key must be the same length as the block size of the [digest] in use. Therefore, if the original key is
     * longer than the block size we first hash it, then pad it with null bytes till the required length is reached.
     * If it's smaller than the block size, we just pad it with null bytes.
     *
     * The padded key is XOR with the opad and this value is saved as variable. The padded key is XOR with the ipad
     * and this is also saved as a variable. Then we compute the hash of latter variable concatenated with [msg] and
     * compute the hash with first stored variable concatenated with this hash. This is given back as the MAC.
     *
     * @param msg The message whose MAC has to be calculated
     * @return The MAC as a [UByteArray]
     */
    override fun generate(msg: UByteArray): UByteArray {
        val opad = UByteArray(digest.blockSize()) { 0x5cu}
        val ipad = UByteArray(digest.blockSize()) { 0x36u}

        var kPrime = if (key.size > digest.blockSize()) {
            digest.getInstance().hash(key)
        } else {
            key
        }
        if (kPrime.size < digest.blockSize() ) {
            kPrime += UByteArray(digest.blockSize() - kPrime.size)
        }

        require(kPrime.size == digest.blockSize()) {"K' must be the same size as the " +
                "block size of the used digest method"}

        val firstPart = kPrime xor opad

        var secondPart = kPrime xor ipad

        secondPart = digest.getInstance().hash(secondPart + msg)

        return digest.hash(firstPart + secondPart)
    }

}