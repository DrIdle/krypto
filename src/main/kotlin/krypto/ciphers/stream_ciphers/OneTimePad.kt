package krypto.ciphers.stream_ciphers

import krypto.utils.xor

/**
 * Class implementing the One-Time-Pad stream cipher
 */
@OptIn(ExperimentalUnsignedTypes::class)
class OneTimePad {

    /**
     * Encrypting and decrypting a given msg with a key
     *
     * The One-Time pad stream cipher is very basic: the msg is XOR-ed with key. Therefore, the encryption and decryption
     * is the same. The only thing we have to check is whether [informationByteArray]
     * and [keyByteArray] are of the same size.
     *
     * @param informationByteArray The msg to be encrypted or decrypted
     * @param keyByteArray The key used for encryption or decryption
     * @return The encrypted or decrypted msg
     */
    fun encodeAndDecode(informationByteArray: UByteArray, keyByteArray: UByteArray): UByteArray {
        if (informationByteArray.size != keyByteArray.size) {
            throw IllegalArgumentException("THe key must be as long as the information to be encoded")
        }
        return informationByteArray xor keyByteArray
    }
}