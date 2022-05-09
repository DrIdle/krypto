package krypto.mac

import krypto.ciphers.block_ciphers.DES

@OptIn(ExperimentalUnsignedTypes::class)
class CBCMAC(key: UByteArray): MACInterface {

    private val encoder = DES(key, "CBC")

    init {
        encoder.iv = ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u)
    }

    override fun generate(msg: UByteArray): UByteArray {
        return encoder.encrypt(msg).takeLast(8).toUByteArray()
    }
}
