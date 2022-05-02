package krypto.utils

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@OptIn(ExperimentalUnsignedTypes::class)
class UtilsTest {

    @Test
    fun `strxor should give back the correct value`() {
        val testString = "ABC"
        val testKey = "1+1"
        val charset = Charsets.US_ASCII
        Assertions.assertEquals("pir", testString.strxor(testKey, charset))
    }

    @Test
    fun `strxor should throw exception when unequal length is given`() {
        val testString = "ABC"
        val testKey = "1+"
        val charset = Charsets.US_ASCII
        assertThrows<IllegalArgumentException> {
            testString.strxor(testKey, charset)
        }
    }

    @Test
    fun `toUInt() should give back the correct value`() {
        val ten: UInt = 10u
        val testArray = ubyteArrayOf(ten.toUByte())
        Assertions.assertEquals(10u, testArray.toUInt())
    }

    @Test
    fun `toUInt() should throw exception for an array that is longer than 4`() {
        val testArray = ubyteArrayOf(0u, 1u, 3u, 4u, 5u, 6u)
        assertThrows<Exception> {
            testArray.toUInt()
        }
    }

    @Test
    fun `toULong should give back the correct value`() {
        val ten: ULong = 10u
        val testArray = ubyteArrayOf(ten.toUByte())
        Assertions.assertEquals(ten, testArray.toULong())
    }

    @Test
    fun `toULong should throw exception for an array that is longer than 8`() {
        val testArray = ubyteArrayOf(0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u)
        assertThrows<Exception> {
            testArray.toULong()
        }
    }

    @Test
    fun `littleEndian() gives back the correct value`() {
        val testArray1: UByteArray = ubyteArrayOf(0.toUByte(), 0.toUByte(), 0.toUByte(), 0.toUByte())
        val testArray2: UByteArray = ubyteArrayOf(86u, 75u, 30u, 9u)
        val testArray3: UByteArray = ubyteArrayOf(255u, 255u, 255u, 250u)

        val testOutput1 = "0x00000000"
        val testOutput2 = "0x091e4b56"
        val testOutput3 = "0xfaffffff"

        Assertions.assertEquals(testOutput1, "0x"+testArray1.littleEndian().toString(16).padStart(8, '0'))
        Assertions.assertEquals(testOutput2, "0x"+testArray2.littleEndian().toString(16).padStart(8, '0'))
        Assertions.assertEquals(testOutput3, "0x"+testArray3.littleEndian().toString(16).padStart(8, '0'))
    }

    @Test
    fun `littleEndian() should throw exception for array with size other than 4`() {
        val testArray1: UByteArray = ubyteArrayOf(86u, 75u, 30u)
        val testArray2: UByteArray = ubyteArrayOf(255u, 255u, 255u, 250u, 32u)

        assertThrows<Exception> {
            testArray1.littleEndian()
        }

        assertThrows<Exception> {
            testArray2.littleEndian()
        }
    }

    @Test
    fun `revLittleEndian() gives back the correct value`() {
        val testInput1 = 0x00000000u
        val testInput2 = 0x091e4b56u
        val testInput3 = 0xfaffffffu

        val testArray1: UByteArray = ubyteArrayOf(0.toUByte(), 0.toUByte(), 0.toUByte(), 0.toUByte())
        val testArray2: UByteArray = ubyteArrayOf(86u, 75u, 30u, 9u)
        val testArray3: UByteArray = ubyteArrayOf(255u, 255u, 255u, 250u)

        Assertions.assertEquals(testArray1.toList(), testInput1.revLittleEndian().toList())
        Assertions.assertEquals(testArray2.toList(), testInput2.revLittleEndian().toList())
        Assertions.assertEquals(testArray3.toList(), testInput3.revLittleEndian().toList())
    }

    @Test
    fun `ToUByteArray extension of String should work correctly`() {
        val testInput = "0000000100000011000001111111111100000001"

        val output = testInput.toUByteArray()

        val correctOutput = ubyteArrayOf(1u, 3u, 7u, 255u, 1u)

        Assertions.assertEquals(correctOutput.toList(), output.toList())

    }

    @Test
    fun `ToUByteArray should only work with string length which is not dividable with 8`() {
        val testInput = "000000010000001100000111111111110000001"

        assertThrows<Exception>{
            testInput.toUByteArray()
        }

    }

    @Test
    fun `toUByteArray for a UInt should give back the correct value`() {
        val testInput = 10u

        val output = testInput.toUByteArray()
        val correctOutput = ubyteArrayOf(0u, 0u, 0u, 10u)

        Assertions.assertEquals(correctOutput.toList(), output.toList())
    }

    @Test
    fun `toUByteArray for a ULong should give back the correct value`() {
        val testInput: ULong = 10u

        val output = testInput.toUByteArray()
        val correctOutput = ubyteArrayOf(0u, 0u, 0u, 0u, 0u, 0u, 0u, 10u)

        Assertions.assertEquals(correctOutput.toList(), output.toList())
    }

    @Test
    fun `toBinaryStringRep should give back the correct value`() {
        val testArray = ubyteArrayOf(0u, 1u, 2u, 3u)

        val output = testArray.toBinaryStringRep()

        val correctOutput = "00000000000000010000001000000011"

        Assertions.assertEquals(correctOutput, output)
    }

    @Test
    fun `hexdigest should give back the correct value`() {
        val testArray = ubyteArrayOf(0x30u, 0xfeu, 0xdau)

        val output = testArray.hexdigest()

        val correctOutput = "30feda"

        Assertions.assertEquals(correctOutput, output)
    }
}