package krypto.ciphers.block_ciphers

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

@OptIn(ExperimentalUnsignedTypes::class)
class DESTest {

    private val testKey = ubyteArrayOf(0x10u, 0x31u, 0x6Eu, 0x02u, 0x8Cu, 0x8Fu, 0x3Bu, 0x4au)

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


}