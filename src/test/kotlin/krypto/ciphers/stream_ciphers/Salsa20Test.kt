package krypto.ciphers.stream_ciphers

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@OptIn(ExperimentalUnsignedTypes::class)
class Salsa20Test {

    private val salsaTestKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    private val salsaNonce: ULong = 0u
    private val charset = Charsets.US_ASCII
    private val wrongLengthKey = "AA"

    @Test
    fun `Quaterround works in the right way`() {

        val salsaEncoder = Salsa20(salsaTestKey.toByteArray(charset = charset).toUByteArray(), salsaNonce)
        val qrInput1 = uintArrayOf(0u, 0u, 0u, 0u)
        val qrInput2 = uintArrayOf(1u, 0u, 0u, 0u)
        val qrInput3 = uintArrayOf(0u, 1u, 0u, 0u)
        val qrInput4 = uintArrayOf(0u, 0u, 1u, 0u)
        val qrInput5 = uintArrayOf(0u, 0u, 0u, 1u)
        val qrInput6 = uintArrayOf(0xe7e8c006u, 0xc4f9417du, 0x6479b4b2u, 0x68c67137u)
        val qrInput7 = uintArrayOf(0xd3917c5bu, 0x55f1c407u, 0x52a58a7au, 0x8f887a3bu)
        val qrOutput1 = uintArrayOf(0u, 0u, 0u, 0u)
        val qrOutput2 = uintArrayOf(0x08008145u, 0x00000080u, 0x00010200u, 0x20500000u)
        val qrOutput3 = uintArrayOf(0x88000100u, 0x00000001u, 0x00000200u, 0x00402000u)
        val qrOutput4 = uintArrayOf(0x80040000u, 0x00000000u, 0x00000001u, 0x00002000u)
        val qrOutput5 = uintArrayOf(0x00048044u, 0x00000080u, 0x00010000u, 0x20100001u)
        val qrOutput6 = uintArrayOf(0xe876d72bu, 0x9361dfd5u, 0xf1460244u, 0x948541a3u)
        val qrOutput7 = uintArrayOf(0x3e2f308cu, 0xd90a8f36u, 0x6ab2a923u, 0x2883524cu)

        Assertions.assertEquals(qrOutput1.toList(), salsaEncoder.quarterRound(qrInput1).toList())
        Assertions.assertEquals(qrOutput2.toList(), salsaEncoder.quarterRound(qrInput2).toList())
        Assertions.assertEquals(qrOutput3.toList(), salsaEncoder.quarterRound(qrInput3).toList())
        Assertions.assertEquals(qrOutput4.toList(), salsaEncoder.quarterRound(qrInput4).toList())
        Assertions.assertEquals(qrOutput5.toList(), salsaEncoder.quarterRound(qrInput5).toList())
        Assertions.assertEquals(qrOutput6.toList(), salsaEncoder.quarterRound(qrInput6).toList())
        Assertions.assertEquals(qrOutput7.toList(), salsaEncoder.quarterRound(qrInput7).toList())
    }

    @Test
    fun `Columnround works right`() {
        val salsaEncoder = Salsa20(salsaTestKey.toByteArray(charset = charset).toUByteArray(), salsaNonce)
        val crInput1 = uintArrayOf(
            1u, 0u, 0u, 0u,
            1u, 0u, 0u, 0u,
            1u, 0u, 0u, 0u,
            1u, 0u, 0u, 0u
        )
        val crInput2 = uintArrayOf(
            0x08521bd6u, 0x1fe88837u, 0xbb2aa576u, 0x3aa26365u,
            0xc54c6a5bu, 0x2fc74c2fu, 0x6dd39cc3u, 0xda0a64f6u,
            0x90a2f23du, 0x067f95a6u, 0x06b35f61u, 0x41e4732eu,
            0xe859c100u, 0xea4d84b7u, 0x0f619bffu, 0xbc6e965au)

        val crOutput1 = uintArrayOf(
            0x10090288u, 0x00000000u, 0x00000000u, 0x00000000u,
            0x00000101u, 0x00000000u, 0x00000000u, 0x00000000u,
            0x00020401u, 0x00000000u, 0x00000000u, 0x00000000u,
            0x40a04001u, 0x00000000u, 0x00000000u, 0x00000000u)
        val crOutput2 = uintArrayOf(
            0x8c9d190au, 0xce8e4c90u, 0x1ef8e9d3u, 0x1326a71au,
            0x90a20123u, 0xead3c4f3u, 0x63a091a0u, 0xf0708d69u,
            0x789b010cu, 0xd195a681u, 0xeb7d5504u, 0xa774135cu,
            0x481c2027u, 0x53a8e4b5u, 0x4c1f89c5u, 0x3f78c9c8u)

        Assertions.assertEquals(crOutput1.toList(), salsaEncoder.columnRound(crInput1).toList())
        Assertions.assertEquals(crOutput2.toList(), salsaEncoder.columnRound(crInput2).toList())
    }

    @Test
    fun `Rowround works right`() {
        val salsaEncoder = Salsa20(salsaTestKey.toByteArray(charset = charset).toUByteArray(), salsaNonce)
        val rrInput1 = uintArrayOf(
            1u, 0u, 0u, 0u,
            1u, 0u, 0u, 0u,
            1u, 0u, 0u, 0u,
            1u, 0u, 0u, 0u
        )
        val rrInput2 = uintArrayOf(
            0x08521bd6u, 0x1fe88837u, 0xbb2aa576u, 0x3aa26365u,
            0xc54c6a5bu, 0x2fc74c2fu, 0x6dd39cc3u, 0xda0a64f6u,
            0x90a2f23du, 0x067f95a6u, 0x06b35f61u, 0x41e4732eu,
            0xe859c100u, 0xea4d84b7u, 0x0f619bffu, 0xbc6e965au)

        val rrOutput1 = uintArrayOf(
            0x08008145u, 0x00000080u, 0x00010200u, 0x20500000u,
            0x20100001u, 0x00048044u, 0x00000080u, 0x00010000u,
            0x00000001u, 0x00002000u, 0x80040000u, 0x00000000u,
            0x00000001u, 0x00000200u, 0x00402000u, 0x88000100u)
        val rrOutput2 = uintArrayOf(
            0xa890d39du, 0x65d71596u, 0xe9487daau, 0xc8ca6a86u,
            0x949d2192u, 0x764b7754u, 0xe408d9b9u, 0x7a41b4d1u,
            0x3402e183u, 0x3c3af432u, 0x50669f96u, 0xd89ef0a8u,
            0x0040ede5u, 0xb545fbceu, 0xd257ed4fu, 0x1818882du)

        Assertions.assertEquals(rrOutput1.toList(), salsaEncoder.rowRound(rrInput1).toList())
        Assertions.assertEquals(rrOutput2.toList(), salsaEncoder.rowRound(rrInput2).toList())
    }

    @Test
    fun `Doubleround works right`() {
        val salsaEncoder = Salsa20(salsaTestKey.toByteArray(charset = charset).toUByteArray(), salsaNonce)
        val drInput1 = uintArrayOf(
            1u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u
        )
        val drInput2 = uintArrayOf(
            0xde501066u, 0x6f9eb8f7u, 0xe4fbbd9bu, 0x454e3f57u,
            0xb75540d3u, 0x43e93a4cu, 0x3a6f2aa0u, 0x726d6b36u,
            0x9243f484u, 0x9145d1e8u, 0x4fa9d247u, 0xdc8dee11u,
            0x054bf545u, 0x254dd653u, 0xd9421b6du, 0x67b276c1u)

        val drOutput1 = uintArrayOf(
            0x8186a22du, 0x0040a284u, 0x82479210u, 0x06929051u,
            0x08000090u, 0x02402200u, 0x00004000u, 0x00800000u,
            0x00010200u, 0x20400000u, 0x08008104u, 0x00000000u,
            0x20500000u, 0xa0000040u, 0x0008180au, 0x612a8020u)
        val drOutput2 = uintArrayOf(
            0xccaaf672u, 0x23d960f7u, 0x9153e63au, 0xcd9a60d0u,
            0x50440492u, 0xf07cad19u, 0xae344aa0u, 0xdf4cfdfcu,
            0xca531c29u, 0x8e7943dbu, 0xac1680cdu, 0xd503ca00u,
            0xa74b2ad6u, 0xbc331c5cu, 0x1dda24c7u, 0xee928277u)

        Assertions.assertEquals(drOutput1.toList(), salsaEncoder.doubleRound(drInput1).toList())
        Assertions.assertEquals(drOutput2.toList(), salsaEncoder.doubleRound(drInput2).toList())
    }

    @Test
    fun `salsaHash gives back the correct value`() {
        val salsaEncoder = Salsa20(salsaTestKey.toByteArray(charset = charset).toUByteArray(), salsaNonce)

        val hashInput1 = ubyteArrayOf(
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u)

        val hashInput2 = ubyteArrayOf(
            211u,159u, 13u,115u, 76u, 55u, 82u,183u, 3u,117u,222u, 37u,191u,187u,234u,136u,
            49u,237u,179u, 48u, 1u,106u,178u,219u,175u,199u,166u, 48u, 86u, 16u,179u,207u,
            31u,240u, 32u, 63u, 15u, 83u, 93u,161u,116u,147u, 48u,113u,238u, 55u,204u, 36u,
            79u,201u,235u, 79u, 3u, 81u,156u, 47u,203u, 26u,244u,243u, 88u,118u,104u, 54u)

        val hashInput3 = ubyteArrayOf(
            88u,118u,104u, 54u, 79u,201u,235u, 79u, 3u, 81u,156u, 47u,203u, 26u,244u,243u,
            191u,187u,234u,136u,211u,159u, 13u,115u, 76u, 55u, 82u,183u, 3u,117u,222u, 37u,
            86u, 16u,179u,207u, 49u,237u,179u, 48u, 1u,106u,178u,219u,175u,199u,166u, 48u,
            238u, 55u,204u, 36u, 31u,240u, 32u, 63u, 15u, 83u, 93u,161u,116u,147u, 48u,113u)

        val hashOutput1 = ubyteArrayOf(
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u)

        val hashOutput2 = ubyteArrayOf(
            109u, 42u,178u,168u,156u,240u,248u,238u,168u,196u,190u,203u, 26u,110u,170u,154u,
            29u, 29u,150u, 26u,150u, 30u,235u,249u,190u,163u,251u, 48u, 69u,144u, 51u, 57u,
            118u, 40u,152u,157u,180u, 57u, 27u, 94u,107u, 42u,236u, 35u, 27u,111u,114u,114u,
            219u,236u,232u,135u,111u,155u,110u, 18u, 24u,232u, 95u,158u,179u, 19u, 48u,202u)

        val hashOutput3 = ubyteArrayOf(
            179u, 19u, 48u,202u,219u,236u,232u,135u,111u,155u,110u, 18u, 24u,232u, 95u,158u,
            26u,110u,170u,154u,109u, 42u,178u,168u,156u,240u,248u,238u,168u,196u,190u,203u,
            69u,144u, 51u, 57u, 29u, 29u,150u, 26u,150u, 30u,235u,249u,190u,163u,251u, 48u,
            27u,111u,114u,114u,118u, 40u,152u,157u,180u, 57u, 27u, 94u,107u, 42u,236u, 35u)

        Assertions.assertEquals(hashOutput1.toList(), salsaEncoder.salsa20Hash(hashInput1).toList())
        Assertions.assertEquals(hashOutput2.toList(), salsaEncoder.salsa20Hash(hashInput2).toList())
        Assertions.assertEquals(hashOutput3.toList(), salsaEncoder.salsa20Hash(hashInput3).toList())
    }

    @Test
    fun `salsa20Expand works in the correct way`() {
        val salsaEncoder = Salsa20(salsaTestKey.toByteArray(charset = charset).toUByteArray(), salsaNonce)

        val k0 = ubyteArrayOf(1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u)
        val k1 = ubyteArrayOf(201u, 202u, 203u, 204u, 205u, 206u, 207u, 208u, 209u, 210u, 211u, 212u, 213u, 214u, 215u, 216u)
        val n = ubyteArrayOf(101u, 102u, 103u, 104u, 105u, 106u, 107u, 108u, 109u, 110u, 111u, 112u, 113u, 114u, 115u, 116u)

        val testOutput1 = ubyteArrayOf(
            69u, 37u, 68u, 39u, 41u, 15u,107u,193u,255u,139u,122u, 6u,170u,233u,217u, 98u,
            89u,144u,182u,106u, 21u, 51u,200u, 65u,239u, 49u,222u, 34u,215u,114u, 40u,126u,
            104u,197u, 7u,225u,197u,153u, 31u, 2u,102u, 78u, 76u,176u, 84u,245u,246u,184u,
            177u,160u,133u,130u, 6u, 72u,149u,119u,192u,195u,132u,236u,234u,103u,246u, 74u)

        val testOutput2 = ubyteArrayOf(
            39u,173u, 46u,248u, 30u,200u, 82u, 17u, 48u, 67u,254u,239u, 37u, 18u, 13u,247u,
            241u,200u, 61u,144u, 10u, 55u, 50u,185u, 6u, 47u,246u,253u,143u, 86u,187u,225u,
            134u, 85u,110u,246u,161u,163u, 43u,235u,231u, 94u,171u, 51u,145u,214u,112u, 29u,
            14u,232u, 5u, 16u,151u,140u,183u,141u,171u, 9u,122u,181u,104u,182u,177u,193u
        )

        Assertions.assertEquals(testOutput1.toList(), salsaEncoder.salsa20Expansion(k0+k1, n).toList())
        Assertions.assertEquals(testOutput2.toList(), salsaEncoder.salsa20Expansion(k0, n).toList())
    }

    @Test
    fun `Encoding works correctly`() {
        // Values taken from: https://github.com/das-labor/legacy/blob/master/microcontroller-2/arm-crypto-lib/testvectors/salsa20-256.64-verified.test-vectors
        val testKey = ubyteArrayOf(
            128u,0u,0u,0u,0u,0u,0u,0u,
            0u,0u,0u,0u,0u,0u,0u,0u,
            0u,0u,0u,0u,0u,0u,0u,0u,
            0u,0u,0u,0u,0u,0u,0u,0u)

        val testNonce: ULong = 0u

        val salsaEncoder = Salsa20(key = testKey, nonce = testNonce)

        val testText = UByteArray(512)

        val encryptedText = salsaEncoder.encodeDecode(testText)

        val encryptedTextChunks = encryptedText.toList().chunked(64)

        var xorDigest = UByteArray(64)

        encryptedTextChunks.forEach {
            xorDigest = xorDigest.zip(it.toUByteArray()) {
                oneUByte, otherUByte ->

                oneUByte xor otherUByte
            }.toUByteArray()
        }

        val expectedOutput = ("50EC2485637DB19C6E795E9C739382806F6DB320FE3D0444D56707D7B456457" +
                "F3DB3E8D7065AF375A225A70951C8AB744EC4D595E85225F08E2BC03FE1C42567").lowercase()
        val actualOutputSb = StringBuilder()
        xorDigest.forEach { actualOutputSb.append(it.toString(16).padStart(2,'0')) }
        Assertions.assertEquals(expectedOutput, actualOutputSb.toString())

    }

    @Test
    fun `Not equal lengths should throw exception`() {
        assertThrows<IllegalArgumentException>{
            val encoder = Salsa20(wrongLengthKey.toByteArray(charset = charset).toUByteArray(), salsaNonce)
        }
    }
}