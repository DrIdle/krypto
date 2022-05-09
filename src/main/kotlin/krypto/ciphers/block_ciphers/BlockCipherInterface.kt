package krypto.ciphers.block_ciphers

/**
 * Interface for the block ciphers to implement
 *
 * Provides the basic functions that a block cipher should have:
 * - encrypting a block
 * - decrypting a block
 * - encrypting a whole msg
 * - decrypting a whole msg
 *
 * Note that functions for padding is not added here, because some ciphers might reject a msg which is
 * not a multiple of the block size.
 */
@OptIn(ExperimentalUnsignedTypes::class)
interface BlockCipherInterface {

    fun encryptBlock(msg: UByteArray): UByteArray

    fun decryptBlock(c: UByteArray): UByteArray

    fun encrypt(msg: UByteArray): UByteArray

    fun decrypt(c: UByteArray): UByteArray
}