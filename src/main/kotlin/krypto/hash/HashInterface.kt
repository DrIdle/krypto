package krypto.hash

/**
 * Interface for the hash functions to implement
 *
 * Provides the basic functions that a hash functions should have:
 * - A way to get the block size
 * - A way to get the digest size
 * - A method for hash data
 * - A method for getting an instance of the hash function
 */
@OptIn(ExperimentalUnsignedTypes::class)
interface HashInterface {

    fun blockSize(): Int

    fun digestSize(): Int

    fun hash(m: UByteArray): UByteArray

    fun getInstance(): HashInterface
}