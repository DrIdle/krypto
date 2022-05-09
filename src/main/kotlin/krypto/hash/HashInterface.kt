package krypto.hash

@OptIn(ExperimentalUnsignedTypes::class)
interface HashInterface {

    fun blockSize(): Int

    fun digestSize(): Int

    fun hash(m: UByteArray): UByteArray

    fun getInstance(): HashInterface
}