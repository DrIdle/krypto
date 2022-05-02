package krypto.hash

import krypto.utils.hexdigest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@OptIn(ExperimentalUnsignedTypes::class)
class SHA1Test {

    @Test
    fun `The hash of the empty should be correct`() {
        val testString: String = ""
        val uByteArray = testString.toByteArray(charset = Charsets.US_ASCII).toUByteArray()
        val sha1 = SHA1()
        val hash = sha1.hash(uByteArray)

        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", hash.hexdigest())
    }

    @Test
    fun `The hash of the well known string should be correct`() {
        val testString: String = "The quick brown fox jumps over the lazy dog"
        val uByteArray = testString.toByteArray(charset = Charsets.US_ASCII).toUByteArray()
        val sha1 = SHA1()
        val hash = sha1.hash(uByteArray)

        assertEquals("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", hash.hexdigest())
    }

    @Test
    fun `The f function should give back the correct value based on i`() {
        val testValue1: UInt = 0x89abcdefu
        val testValue2: UInt = 0xfedcba98u
        val testValue3: UInt = 0x01234567u

        val testI1 = 1
        val testI2 = 20
        val testI3 = 40
        val testI4 = 60
        val testI5 = 340

        val testOutput1 = 0x88888888u
        val testOutput2 = 0x76543210u
        val testOutput3 = 0x89abcdefu
        val testOutput4 = 0x76543210u

        val sha1 = SHA1()

        assertEquals(testOutput1.toString(16), sha1.f(testValue1, testValue2, testValue3, testI1).toString(16))
        assertEquals(testOutput2.toString(16), sha1.f(testValue1, testValue2, testValue3, testI2).toString(16))
        assertEquals(testOutput3.toString(16), sha1.f(testValue1, testValue2, testValue3, testI3).toString(16))
        assertEquals(testOutput4.toString(16), sha1.f(testValue1, testValue2, testValue3, testI4).toString(16))
        assertThrows<RuntimeException> {
            sha1.f(testValue1, testValue2, testValue3, testI5)
        }
    }

    @Test
    fun `The k function should give back the correct value based on i`() {
        val testI1 = 1
        val testI2 = 20
        val testI3 = 40
        val testI4 = 60
        val testI5 = 340

        val testOutput1 = 0x5A827999u
        val testOutput2 = 0x6ED9EBA1u
        val testOutput3 = 0x8F1BBCDCu
        val testOutput4 = 0xCA62C1D6u

        val sha1 = SHA1()

        assertEquals(testOutput1, sha1.k(testI1))
        assertEquals(testOutput2, sha1.k(testI2))
        assertEquals(testOutput3, sha1.k(testI3))
        assertEquals(testOutput4, sha1.k(testI4))
        assertThrows<RuntimeException> {
            sha1.k(testI5)
        }

    }
}