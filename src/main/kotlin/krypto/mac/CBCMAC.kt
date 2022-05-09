package krypto.mac

import krypto.ciphers.block_ciphers.DES

/**
 * This class implements the CBC-MAC algorithm
 *
 * The CBC-MAC algorithm uses DES to generate the MAC of the message. The inner workings of the algorithm can be found
 * here: https://en.wikipedia.org/wiki/CBC-MAC
 *
 * @property encoder The DES encoder to be used during the generation of the MAC
 */
@OptIn(ExperimentalUnsignedTypes::class)
class CBCMAC(key: UByteArray): MACInterface {

    private val encoder = DES(key, "CBC")

    // The iv of the encoder has to be set to all nulls
    init {
        encoder.iv = ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u)
    }

    /**
     * Generating the MAC of the msg
     *
     * We encrypt the msg with the [encoder] and take the last encrypted block as the MAC value.
     *
     * @param msg The message whose MAC has to be calculated
     * @return The MAC as a [UByteArray]
     */
    override fun generate(msg: UByteArray): UByteArray {
        return encoder.encrypt(msg).takeLast(8).toUByteArray()
    }
}
