package krypto.mac

@OptIn(ExperimentalUnsignedTypes::class)
interface MACInterface {

    fun generate(msg: UByteArray): UByteArray
}