package krypto.hash

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

@OptIn(ExperimentalUnsignedTypes::class)
class MD5Test {

    @Test
    fun `The hash of the empty should be correct`() {
        val testString: String = ""
        val uByteArray = testString.toByteArray(charset = Charsets.US_ASCII).toUByteArray()
        val md5 = MD5()
        val hash = md5.hash(uByteArray)

        assertEquals("d41d8cd98f00b204e9800998ecf8427e", hash)
    }

    @Test
    fun `The hash of the well known string should be correct`() {
        val testString: String = "The quick brown fox jumps over the lazy dog"
        val uByteArray = testString.toByteArray(charset = Charsets.US_ASCII).toUByteArray()
        val md5 = MD5()
        val hash = md5.hash(uByteArray)

        assertEquals("9e107d9d372bb6826bd81d3542a419d6", hash)
    }
}