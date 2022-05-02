package krypto.hash

import krypto.utils.hexdigest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@OptIn(ExperimentalUnsignedTypes::class)
class MD5Test {

    @Test
    fun `The hash of the empty should be correct`() {
        val testString: String = ""
        val uByteArray = testString.toByteArray(charset = Charsets.US_ASCII).toUByteArray()
        val md5 = MD5()
        val hash = md5.hash(uByteArray)

        assertEquals("d41d8cd98f00b204e9800998ecf8427e", hash.hexdigest())
    }

    @Test
    fun `The f function should give back the correct value based on i`() {
        val testValue1: UInt = 0x89abcdefu
        val testValue2: UInt = 0xfedcba98u
        val testValue3: UInt = 0x01234567u

        val testI1 = 1
        val testI2 = 16
        val testI3 = 32
        val testI4 = 48
        val testI5 = 340

        val testOutput1 = 0x88888888u
        val testOutput2 = 0xffffffffu
        val testOutput3 = 0x76543210u
        val testOutput4 = 0x01234567u

        val md5 = MD5()

        assertEquals(testOutput1.toString(16), md5.f(testValue1, testValue2, testValue3, testI1).toString(16))
        assertEquals(testOutput2.toString(16), md5.f(testValue1, testValue2, testValue3, testI2).toString(16))
        assertEquals(testOutput3.toString(16), md5.f(testValue1, testValue2, testValue3, testI3).toString(16))
        assertEquals(testOutput4.toString(16), md5.f(testValue1, testValue2, testValue3, testI4).toString(16))
        assertThrows<RuntimeException> {
            md5.f(testValue1, testValue2, testValue3, testI5)
        }
    }

    @Test
    fun `The g function should give back the correct value based on i`() {
        val testI1 = 1
        val testI2 = 16
        val testI3 = 32
        val testI4 = 48
        val testI5 = 340

        val testOutput1 = 1
        val testOutput2 = 1
        val testOutput3 = 5
        val testOutput4 = 0

        val md5 = MD5()

        assertEquals(testOutput1, md5.g(testI1))
        assertEquals(testOutput2, md5.g(testI2))
        assertEquals(testOutput3, md5.g(testI3))
        assertEquals(testOutput4, md5.g(testI4))
        assertThrows<RuntimeException> {
            md5.k(testI5)
        }
    }

    @Test
    fun `The hash of the well known string should be correct`() {
        val testString: String = "The quick brown fox jumps over the lazy dog"
        val uByteArray = testString.toByteArray(charset = Charsets.US_ASCII).toUByteArray()
        val md5 = MD5()
        val hash = md5.hash(uByteArray)

        assertEquals("9e107d9d372bb6826bd81d3542a419d6", hash.hexdigest())
    }
}