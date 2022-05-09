package krypto.mac

/**
 * Interface for MACs to implement
 *
 * Provides the basic functions that a block cipher should have:
 * - generating the MAC of a msg
 */
@OptIn(ExperimentalUnsignedTypes::class)
interface MACInterface {

    fun generate(msg: UByteArray): UByteArray
}