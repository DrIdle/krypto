package krypto.utils

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

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
    fun `toInt() should give back the correct value`() {
        val ten = 10
        val testArray = byteArrayOf(ten.toByte())
        Assertions.assertEquals(10, testArray.toInt())
    }

    @Test
    fun `toUInt() should give back the correct value`() {
        val ten: UInt = 10u
        val testArray = ubyteArrayOf(ten.toUByte())
        Assertions.assertEquals(10u, testArray.toUInt())
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
}