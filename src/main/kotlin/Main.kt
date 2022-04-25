import krypto.ciphers.block_ciphers.DES

@OptIn(ExperimentalUnsignedTypes::class)
fun main() {
    val testKey = ubyteArrayOf(0b00010011u, 0b00110100u, 0b01010111u, 0b01111001u, 0b10011011u, 0b10111100u, 0b11011111u, 0b11110001u)
    val testMsg = ubyteArrayOf(0x01u,0x23u,0x45u,0x67u,0x89u,0xABu,0xCDu,0xEFu)

    val encoder = DES(testKey)
    val cipherText = encoder.encrypt(testMsg)
    cipherText.forEach {
        print(it.toString(16).padStart(2, '0'))
    }
}