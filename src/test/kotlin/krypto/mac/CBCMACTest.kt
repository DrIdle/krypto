package krypto.mac

import krypto.utils.hexdigest
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

@OptIn(ExperimentalUnsignedTypes::class)
class CBCMACTest {

    private val testKey = ubyteArrayOf(0b00010011u, 0b00110100u, 0b01010111u, 0b01111001u, 0b10011011u, 0b10111100u, 0b11011111u, 0b11110001u)
    private val testMsg = ubyteArrayOf(0x01u,0x23u,0x45u,0x67u,0x89u,0xABu,0xCDu,0xEFu)

    @Test
    fun `CBCMAC should give back the correct value`() {
        val correctOutput = "b8df615c66ca5b29"

        val mac = CBCMAC(testKey)
        val output = mac.generate(testMsg)

        Assertions.assertEquals(correctOutput, output.hexdigest())
    }
}