import krypto.ciphers.block_ciphers.DES

@OptIn(ExperimentalUnsignedTypes::class)
fun main() {
    val testKey = ubyteArrayOf(0x10u, 0x31u, 0x6Eu, 0x02u, 0x8Cu, 0x8Fu, 0x3Bu, 0x4au)
    val testMsg = ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u)

    val encoder = DES(testKey)
    val cipherText = encoder.encrypt(testMsg)
    cipherText.forEach {
        print(it.toString(16).padStart(2, '0'))
    }
}