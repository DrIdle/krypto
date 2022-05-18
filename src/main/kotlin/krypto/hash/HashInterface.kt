package krypto.hash

/**
 * Interface for the hash functions to implement
 *
 * Provides the basic functions that a hash functions should have
 */
@OptIn(ExperimentalUnsignedTypes::class)
sealed interface HashInterface {

    /**
     * A way to get the block size
     *
     * @return The block size of the hash function
     */
    fun blockSize(): Int

    /**
     * A way to get the digest size
     *
     * @return The digest size of the hash function
     */
    fun digestSize(): Int

    /**
     * Hash the data
     *
     * @param m The date to be hashed
     * @return The hash of the data
     */
    fun hash(m: UByteArray): UByteArray

    /**
     * Returns an instance of the hash function
     *
     * @return An instance of the hash function
     */
    fun getInstance(): HashInterface
}