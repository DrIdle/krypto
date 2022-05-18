package krypto.mac

/**
 * Interface for MACs to implement
 *
 * Provides the basic functions that a block cipher should have
 *
 */
@OptIn(ExperimentalUnsignedTypes::class)
sealed interface MACInterface {

    /**
     * Generating the MAC of a msg
     *
     * @param msg The msg whose MAC should be generated
     * @return The MAC of the msg
     */
    fun generate(msg: UByteArray): UByteArray
}