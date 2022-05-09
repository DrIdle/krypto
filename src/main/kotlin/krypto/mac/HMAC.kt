package krypto.mac

import krypto.hash.HashInterface

@OptIn(ExperimentalUnsignedTypes::class)
class HMAC<T: HashInterface>(private val key: UByteArray, private val digest: T): MACInterface {

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

        val firstPart = kPrime.zip(opad) { keyByte, constantByte ->
            keyByte xor constantByte
        }.toUByteArray()

        var secondPart = kPrime.zip(ipad) { keyByte, constantByte ->
            keyByte xor constantByte
        }.toUByteArray()

        secondPart = digest.getInstance().hash(secondPart + msg)

        return digest.hash(firstPart + secondPart)
    }

}