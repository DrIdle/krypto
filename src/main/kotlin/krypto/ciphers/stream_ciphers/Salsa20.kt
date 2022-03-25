package krypto.ciphers.stream_ciphers

import krypto.utils.toInt
import kotlin.random.Random

class Salsa20(val key: ByteArray, var nonce: Long?) {

    //var internalState = Array(4) { IntArray(4) } // 2D array of size 4x4
    var internalState = IntArray(16)

    private val constant: String = "expand 32-byte k"
    private val charset = Charsets.US_ASCII

    init {
        if (key.size != 32) {
            throw IllegalArgumentException("Key size must be 256 bit (32 byte)")
        }
    }

    private fun qr(a: Int, b: Int, c: Int, d: Int) {
        internalState[b] = internalState[b] xor ((internalState[a] + internalState[d]) shl 7)
        internalState[c] = internalState[c] xor ((internalState[b] + internalState[a]) shl 9)
        internalState[d] = internalState[d] xor ((internalState[c] + internalState[b]) shl 13)
        internalState[a] = internalState[a] xor ((internalState[d] + internalState[c]) shl 18)
    }

    private fun intializeInternalState(key: ByteArray, nonce: Long, counter: Long, ) {

        //Constant positions
        val constantByteList = constant.toByteArray(charset = charset).toList()
        val constantParts = constantByteList.chunked(4)
        /*
        internalState[0][0] = constantParts[0].toByteArray().toInt()
        internalState[1][1] = constantParts[1].toByteArray().toInt()
        internalState[2][2] = constantParts[2].toByteArray().toInt()
        internalState[3][3] = constantParts[3].toByteArray().toInt()
         */
        internalState[0] = constantParts[0].toByteArray().toInt()
        internalState[5] = constantParts[1].toByteArray().toInt()
        internalState[10] = constantParts[2].toByteArray().toInt()
        internalState[15] = constantParts[3].toByteArray().toInt()
        //Key positions
        val keyParts = key.toList().chunked(4)
        /*
        internalState[0][1] = keyParts[0].toByteArray().toInt()
        internalState[0][2] = keyParts[1].toByteArray().toInt()
        internalState[0][3] = keyParts[2].toByteArray().toInt()
        internalState[1][0] = keyParts[3].toByteArray().toInt()
        internalState[2][3] = keyParts[4].toByteArray().toInt()
        internalState[3][0] = keyParts[5].toByteArray().toInt()
        internalState[3][1] = keyParts[6].toByteArray().toInt()
        internalState[3][2] = keyParts[7].toByteArray().toInt()
         */
        internalState[1] = keyParts[0].toByteArray().toInt()
        internalState[2] = keyParts[1].toByteArray().toInt()
        internalState[3] = keyParts[2].toByteArray().toInt()
        internalState[4] = keyParts[3].toByteArray().toInt()
        internalState[11] = keyParts[4].toByteArray().toInt()
        internalState[12] = keyParts[5].toByteArray().toInt()
        internalState[13] = keyParts[6].toByteArray().toInt()
        internalState[14] = keyParts[7].toByteArray().toInt()

        //Counter positiona
        val counterFirstPart = (counter shr 32).toInt()
        val counterSecondPart = (counter shl 32).toInt()
        /*
        internalState[2][0] = counterFirstPart
        internalState[2][1] = counterSecondPart

         */
        internalState[8] = counterFirstPart
        internalState[9] = counterSecondPart

        //Nonce positions
        val nonceFirstPart = (nonce shr 32).toInt()
        val nonceSecondPart = (nonce shl 32).toInt()
        /*
        internalState[1][2] = nonceFirstPart
        internalState[1][3] = nonceSecondPart

         */
        internalState[6] = nonceFirstPart
        internalState[7] = nonceSecondPart

    }

    fun encodeAndDecode(dataBytaArray: ByteArray, startingPosition: Long = 0): ByteArray {
        val numberOfRounds = dataBytaArray.size / 512
        val keyStream = ByteArray(dataBytaArray.size)
        var counter: Long = startingPosition

        nonce = nonce ?: Random.nextLong()

        for (i in 0 until (numberOfRounds+1)) {
            intializeInternalState(key, nonce!!, counter)
            for (j in 0 until 20) {

                //Odd round
                qr(0, 4, 8, 12)
                qr(5, 9, 13, 1)
                qr(10, 14, 2, 6)
                qr(15, 3, 7, 11)
                //Even round
                qr(0, 1, 2, 3)
                qr(5, 6, 7, 4)
                qr(10, 11, 8, 9)
                qr(15, 12, 13, 14)
            }
            if (i < numberOfRounds) {
                internalState.map { it.toByte() }.toByteArray().copyInto(keyStream, destinationOffset = (i * 512))
            }
            else {
                internalState.map { it.toByte() }.toByteArray().copyInto(keyStream, destinationOffset = (i * 512), endIndex = (dataBytaArray.size - (numberOfRounds * 512)) )
            }
            counter++
        }

        val encoder = OneTimePad()

        return encoder.encodeAndDecode(dataBytaArray, keyStream)
    }

}