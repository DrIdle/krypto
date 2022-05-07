package krypto.ciphers.block_ciphers

import krypto.utils.hexdigest
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@OptIn(ExperimentalUnsignedTypes::class)
class DESTest {

    private val testKey = ubyteArrayOf(0b00010011u, 0b00110100u, 0b01010111u, 0b01111001u, 0b10011011u, 0b10111100u, 0b11011111u, 0b11110001u)
    private val testMsg = ubyteArrayOf(0x01u,0x23u,0x45u,0x67u,0x89u,0xABu,0xCDu,0xEFu)

    @Test
    fun `Rotating should give back the correct value`() {
        val testInput1 = "0000000000001101011101000110"
        val testInput2 = "1100000000001101011101000110"
        val testRotationCount = 2
        val encoder = DES(testKey, "ECB")
        val output1 = "0000000000110101110100011000"
        val output2 = "0000000000110101110100011011"
        Assertions.assertEquals(output1, encoder.rotateLeftWithGiven(testInput1, testRotationCount))
        Assertions.assertEquals(output2, encoder.rotateLeftWithGiven(testInput2, testRotationCount))
    }

    @Test
    fun `Permutation should work correctly`() {
        val testInput = "0123456789"
        val testPermutation = intArrayOf(10, 9, 8, 7, 6, 5, 4, 3, 2, 1)

        val encoder = DES(testKey, "ECB")
        val output = "9876543210"
        Assertions.assertEquals(output, encoder.permutation(testInput,testPermutation))
    }

    @Test
    fun `Subkeys should be correctly generated`() {
        val correctOutput = listOf(
            "000110110000001011101111111111000111000001110010",
            "011110011010111011011001110110111100100111100101",
            "010101011111110010001010010000101100111110011001",
            "011100101010110111010110110110110011010100011101",
            "011111001110110000000111111010110101001110101000",
            "011000111010010100111110010100000111101100101111",
            "111011001000010010110111111101100001100010111100",
            "111101111000101000111010110000010011101111111011",
            "111000001101101111101011111011011110011110000001",
            "101100011111001101000111101110100100011001001111",
            "001000010101111111010011110111101101001110000110",
            "011101010111000111110101100101000110011111101001",
            "100101111100010111010001111110101011101001000001",
            "010111110100001110110111111100101110011100111010",
            "101111111001000110001101001111010011111100001010",
            "110010110011110110001011000011100001011111110101")

        val encoder = DES(testKey, "ECB")
        val subkeys = encoder.generateSubKeys()

        Assertions.assertEquals(correctOutput, subkeys)
    }

    @Test
    fun `Exptend should work correctly`() {
        val testInput = "11110000101010101111000010101010"

        val correctOutput = "011110100001010101010101011110100001010101010101"

        val encoder = DES(testKey, "ECB")
        val output = encoder.extended(testInput)

        Assertions.assertEquals(correctOutput, output)
    }

    @Test
    fun `S-box look up should work correctly`() {
        val testInput = "011011"
        val testIndex = 0 // This is S1

        val correctOutput = "0101" // Binary representation of 5

        val encoder = DES(testKey, "ECB")
        val output = encoder.getOutputFromGivenSBox(testInput, testIndex)

        Assertions.assertEquals(correctOutput, output)
    }

    @Test
    fun `Feistel function should work correctly`() {
        val testRight = "11110000101010101111000010101010"
        val testIndex = 0

        val correctOutput = "00100011010010101010100110111011"

        val encoder = DES(testKey, "ECB")
        val output = encoder.feistelFunction(testRight, testIndex)

        Assertions.assertEquals(correctOutput, output)
    }

    @Test
    fun `Padding should work correctly`() {
        val testArray = ubyteArrayOf(0xffu, 0xabu, 0x12u, 0x45u)
        val correctOutput = ubyteArrayOf(0xffu, 0xabu, 0x12u, 0x45u, 0x80u, 0u, 0u, 0u)

        val encoder = DES(testKey, "ECB")
        val output = encoder.pad(testArray.toMutableList())

        Assertions.assertEquals(correctOutput.toList(), output.toList())
    }

    @Test
    fun `Removal of the padding should work correctly`() {
        val testArray = ubyteArrayOf(0xffu, 0xabu, 0x12u, 0x45u, 0x80u, 0u, 0u, 0u)
        val correctOutput = ubyteArrayOf(0xffu, 0xabu, 0x12u, 0x45u)

        val encoder = DES(testKey, "ECB")
        val output = encoder.removePadding(testArray.toMutableList())

        Assertions.assertEquals(correctOutput.toList(), output.toList())
    }

    @Test
    fun `Trying to remove wrong padding should throw exception`() {
        val testArray = ubyteArrayOf(0xffu, 0xabu, 0x12u, 0x45u, 0x86u, 0u, 0u, 0u)

        val encoder = DES(testKey, "ECB")
        assertThrows<IllegalStateException> {
            encoder.removePadding(testArray.toMutableList())
        }
    }

    @Test
    fun `The encryption of one block should work correctly`() {
        val correctOutput = "85e813540f0ab405"

        val encoder = DES(testKey, "ECB")
        val output = encoder.encryptBlock(testMsg)

        Assertions.assertEquals(correctOutput, output.hexdigest())
    }

    @Test
    fun `The decryption of one block should work correctly`() {
        val testInput = ubyteArrayOf(0x85u, 0xe8u, 0x13u, 0x54u, 0x0fu, 0x0au, 0xb4u, 0x05u)

        val encoder = DES(testKey, "ECB")
        val output = encoder.decryptBlock(testInput)

        Assertions.assertEquals(testMsg.toList(), output.toList())
    }

    @Test
    fun `Encryption in ECB mode should work correctly`() {
        val correctOutput = "85e813540f0ab40587ab78d11e188df6"

        val encoder = DES(testKey, "ECB")
        val output = encoder.encrypt(testMsg)

        Assertions.assertEquals(correctOutput, output.hexdigest())
    }

    @Test
    fun `Decryption in ECB mode should work correctly`() {
        val testInput = ubyteArrayOf(0x85u, 0xe8u, 0x13u, 0x54u, 0x0fu, 0x0au, 0xb4u, 0x05u, 0x87u, 0xabu, 0x78u,
            0xd1u, 0x1eu, 0x18u, 0x8du, 0xf6u)

        val encoder = DES(testKey, "ECB")
        val output = encoder.decrypt(testInput)

        Assertions.assertEquals(testMsg.toList(), output.toList())
    }

    @Test
    fun `Encryption in CBC mode should work correctly`() {
        val correctOutput = "85e813540f0ab405b8df615c66ca5b29"
        val testIV = ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u)

        val encoder = DES(testKey, "CBC")
        encoder.iv = testIV
        val output = encoder.encrypt(testMsg)

        Assertions.assertEquals(correctOutput, output.hexdigest())
    }

    @Test
    fun `Decryption in CBC mode should work correctly`() {
        val testInput = ubyteArrayOf(0x85u, 0xe8u, 0x13u, 0x54u, 0x0fu, 0x0au, 0xb4u, 0x05u, 0xb8u, 0xdfu, 0x61u, 0x5cu, 0x66u, 0xcau, 0x5bu, 0x29u)
        val testIV = ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u)

        val encoder = DES(testKey, "CBC")
        encoder.iv = testIV
        val output = encoder.decrypt(testInput)

        Assertions.assertEquals(testMsg.toList(), output.toList())
    }
}