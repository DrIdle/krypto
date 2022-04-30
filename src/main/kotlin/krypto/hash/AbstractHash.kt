package krypto.hash

@OptIn(ExperimentalUnsignedTypes::class)
abstract class AbstractHash {

    abstract fun blockSize(): Int

    abstract fun digestSize(): Int

    abstract fun hash(m: UByteArray): UByteArray

    abstract fun getInstance(): AbstractHash
}