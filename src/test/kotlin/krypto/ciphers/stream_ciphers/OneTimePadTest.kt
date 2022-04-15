package krypto.ciphers.stream_ciphers

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@OptIn(ExperimentalUnsignedTypes::class)
class OneTimePadTest {

    private val text = "AAA"
    private val key = "111"
    private val ciphertext = "ppp"
    private val charset = Charsets.US_ASCII
    private val wrongLengthKey = "1111"

    @Test
    fun `Encoding gives back the correct ciphertext`() {
        val encoder = OneTimePad()
        val encodedText = encoder.encodeAndDecode(text.toByteArray(charset = charset).toUByteArray(),key.toByteArray(charset = charset).toUByteArray())
        assertEquals(ciphertext, encodedText.toByteArray().toString(charset = charset))
    }

    @Test
    fun `Not equal lengths should throw exception`() {
        val encoder = OneTimePad()
        assertThrows<IllegalArgumentException>{
            encoder.encodeAndDecode(text.toByteArray(charset = charset).toUByteArray(), wrongLengthKey.toByteArray(charset = charset).toUByteArray())
        }
    }
}