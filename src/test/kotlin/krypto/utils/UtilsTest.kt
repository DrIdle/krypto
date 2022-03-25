package krypto.utils

import krypto.ciphers.stream_ciphers.OneTimePad
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import kotlin.experimental.xor

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

}