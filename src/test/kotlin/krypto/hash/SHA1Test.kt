package krypto.hash

import krypto.utils.hexdigest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

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
}