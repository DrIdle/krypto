package krypto.mac

import krypto.ciphers.block_ciphers.DES

@OptIn(ExperimentalUnsignedTypes::class)
class CBCMAC(private val key: UByteArray) {

    private val encoder = DES(key, "CBC")

    init {
        encoder.iv = ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u)
    }

    fun generated(msg: UByteArray): UByteArray {
        return encoder.encrypt(msg).takeLast(8).toUByteArray()
    }
}
