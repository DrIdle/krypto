import krypto.ciphers.block_ciphers.DES

@OptIn(ExperimentalUnsignedTypes::class)
fun main() {
    val testKey = ubyteArrayOf(0b00010011u, 0b00110100u, 0b01010111u, 0b01111001u, 0b10011011u, 0b10111100u, 0b11011111u, 0b11110001u)
    val testMsg = ubyteArrayOf(0x01u,0x23u,0x45u,0x67u,0x89u,0xABu,0xCDu,0xEFu)

    val encoder = DES(testKey, "ECB")
    val cipherText = encoder.encrypt(testMsg)
    cipherText.forEach {
        print(it.toString(16).padStart(2, '0'))
    }
    println()
    val plainText = encoder.decrypt(cipherText)
    plainText.forEach {
        print(it.toString(16).padStart(2, '0'))
    }
    println()
    println("Do they match?: ${testMsg.toList() == plainText.toList()}")
    println()

    val testKey2 = ubyteArrayOf(0x10u, 0x31u, 0x6Eu, 0x02u,0x8Cu, 0x8Fu, 0x3Bu, 0x4Au)
    val testMsg2 = ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u)
    val encoder2 = DES(testKey2, "CBC")
    val cipherText2 = encoder2.encrypt(testMsg)
    cipherText2.forEach {
        print(it.toString(16).padStart(2, '0'))
    }
    println()
    val plainText2 = encoder2.decrypt(cipherText2)
    plainText2.forEach {
        print(it.toString(16).padStart(2, '0'))
    }
    println()
    println("Do they match?: ${testMsg.toList() == plainText2.toList()}")
    println()
}