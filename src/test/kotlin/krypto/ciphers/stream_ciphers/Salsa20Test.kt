package krypto.ciphers.stream_ciphers

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class Salsa20Test {

    private val text = "ABC"
    private val salsaTestKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    private val salsaNonce: Long = 1
    private val charset = Charsets.US_ASCII
    private val wrongLengthKey = "AA"


    @Test
    fun `Encoding gives back the correct ciphertext`() {

        val salsaEncoder = Salsa20(salsaTestKey.toByteArray(charset = charset), salsaNonce)
        val encodedInformation = salsaEncoder.encodeAndDecode(text.toByteArray(charset = charset))
        val decodedInformation = salsaEncoder.encodeAndDecode(encodedInformation)
        Assertions.assertEquals(text, decodedInformation.toString(charset = charset))
    }

    @Test
    fun `Not equal lengths should throw exception`() {
        assertThrows<IllegalArgumentException>{
            val encoder = Salsa20(wrongLengthKey.toByteArray(charset = charset), salsaNonce)
        }
    }
}