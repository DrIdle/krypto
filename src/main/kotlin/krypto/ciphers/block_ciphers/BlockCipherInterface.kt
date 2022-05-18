package krypto.ciphers.block_ciphers

/**
 * Interface for the block ciphers to implement
 *
 * Provides the basic functions that a block cipher should have
 *
 * Note that functions for padding is not added here, because some ciphers might reject a msg which is
 * not a multiple of the block size.
 */
@OptIn(ExperimentalUnsignedTypes::class)
sealed interface BlockCipherInterface {

    /**
     * Encrypting a block
     *
     * @param msg The block to encrypt
     * @return The encrypted block
     */
    fun encryptBlock(msg: UByteArray): UByteArray

    /**
     * Decrypting a block
     *
     * @param c The encrypted block
     * @return The decrypted block
     */
    fun decryptBlock(c: UByteArray): UByteArray

    /**
     * Encrypting a whole msg
     *
     * @param msg The msg to encrypt (can be longer than a block)
     * @return The encrypted msg
     */
    fun encrypt(msg: UByteArray): UByteArray

    /**
     * Decrypting a whole msg
     *
     * @param c The encrypted msg
     * @return The decrypted msg
     */
    fun decrypt(c: UByteArray): UByteArray
}