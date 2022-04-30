package krypto.mac

import krypto.hash.MD5
import krypto.hash.SHA1
import krypto.utils.hexdigest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

@OptIn(ExperimentalUnsignedTypes::class)
class HMACTest {

    private val testKeyForHMAC = "key".toByteArray(Charsets.US_ASCII).toUByteArray()
    private val testMsgForHMAC = "The quick brown fox jumps over the lazy dog".toByteArray(Charsets.US_ASCII).toUByteArray()

    @Test
    fun `HMAC-MD5 should give back the correct result`() {
        val testOutput = "80070713463e7749b90c2dc24911e275"

        val hmac = HMAC(testKeyForHMAC, MD5())
        val digest = hmac.generate(testMsgForHMAC)

        assertEquals(testOutput, digest.hexdigest())
    }

    @Test
    fun `HMAC-SHA1 should give back the correct result`() {
        val testOutput = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"

        val hmac = HMAC(testKeyForHMAC, SHA1())
        val digest = hmac.generate(testMsgForHMAC)

        assertEquals(testOutput, digest.hexdigest())
    }
}