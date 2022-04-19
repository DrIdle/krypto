package krypto.ciphers.stream_ciphers

import krypto.utils.toUByteArray
import krypto.utils.toUInt
import kotlin.random.Random

@OptIn(ExperimentalUnsignedTypes::class)
class Salsa20 constructor(private var key: UByteArray, var nonce: Long?) {

    var internalState = UIntArray(16)

    private val constant: String = "expand 32-byte k"
    private val charset = Charsets.US_ASCII
    var savedInternal: UIntArray = UIntArray(16)

    init {
        if (key.size != 32) {
            throw IllegalArgumentException("Key size must be 256 bit (32 byte)")
        }
    }

    fun qr(a: Int, b: Int, c: Int, d: Int) {
        internalState[b] = internalState[b] xor ((internalState[a] + internalState[d]).rotateLeft(7))
        internalState[c] = internalState[c] xor ((internalState[b] + internalState[a]).rotateLeft(9))
        internalState[d] = internalState[d] xor ((internalState[c] + internalState[b]).rotateLeft(13))
        internalState[a] = internalState[a] xor ((internalState[d] + internalState[c]).rotateLeft(18))
    }

    fun initializeInternalState(key: UByteArray, nonce: Long, counter: Long ) {

        //Constant positions
        val constantByteList = constant.toByteArray(charset = charset).toUByteArray().toList()
        val constantParts = constantByteList.chunked(4)
        //internalState[0] = constantParts[0].toUByteArray().toUInt()
        //internalState[5] = constantParts[1].toUByteArray().toUInt()
        //internalState[10] = constantParts[2].toUByteArray().toUInt()
        //internalState[15] = constantParts[3].toUByteArray().toUInt()

        internalState[0] = 0x61707865u
        internalState[5] = 0x3320646eu
        internalState[10] = 0x79622d32u
        internalState[15] = 0x6b206574u

        //Key positions
        val keyParts = key.toList().chunked(4)
        internalState[1] = keyParts[0].toUByteArray().reversedArray().toUInt()
        internalState[2] = keyParts[1].toUByteArray().reversedArray().toUInt()
        internalState[3] = keyParts[2].toUByteArray().reversedArray().toUInt()
        internalState[4] = keyParts[3].toUByteArray().reversedArray().toUInt()
        internalState[11] = keyParts[4].toUByteArray().reversedArray().toUInt()
        internalState[12] = keyParts[5].toUByteArray().reversedArray().toUInt()
        internalState[13] = keyParts[6].toUByteArray().reversedArray().toUInt()
        internalState[14] = keyParts[7].toUByteArray().reversedArray().toUInt()

        //Counter positions
        val counterFirstPart = (counter shr 32).toUInt()
        val counterSecondPart = ((counter shl 32) shr 32).toUInt()
        internalState[8] = counterSecondPart
        internalState[9] = counterFirstPart

        //Nonce positions
        val nonceFirstPart = (nonce shr 32).toUInt().toUByteArray().reversedArray().toUInt()
        val nonceSecondPart = ((nonce shl 32) shr 32).toUInt().toUByteArray().reversedArray().toUInt()
        internalState[6] = nonceFirstPart
        internalState[7] = nonceSecondPart

        savedInternal = internalState.copyOf()

        internalState.forEachIndexed { index, uInt ->
            print("0x${uInt.toString(16).padStart(8, '0')} ")
            if (arrayListOf(3, 7, 11, 15).contains(index)) {
                println()
            }
        }

    }


    fun encodeAndDecode(dataByteArray: UByteArray, startingPosition: Long = 0L): UByteArray {
        val numberOfRounds = dataByteArray.size / 64
        val keyStream = UByteArray(dataByteArray.size)
        var counter: Long = startingPosition

        nonce = nonce ?: Random.nextLong()

        for (i in 0 until (numberOfRounds+1)) {
            initializeInternalState(key, nonce!!, counter)
            for (j in 0 until 10) {
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
                println("After round $j the internal state is:")
                internalState.forEachIndexed { index, uInt ->
                    print("0x${uInt.toString(16).padStart(8, '0')} ")
                    if (arrayListOf(3, 7, 11, 15).contains(index)) {
                        println()
                    }
                }
            }
            val newState: UIntArray = savedInternal.zip(internalState) { saveElement, newElement ->
                saveElement + newElement
            }.toUIntArray()
            if (i < numberOfRounds) {
                newState.map { it.toUByte() }.toUByteArray().copyInto(keyStream, destinationOffset = (i * 64))
            }
            else {
                newState.map { it.toUByte() }.toUByteArray().copyInto(keyStream, destinationOffset = (i * 64), endIndex = (dataByteArray.size - (numberOfRounds * 64)) )
            }
            println("Key stream: ${keyStream.size}")
            keyStream.forEachIndexed { index, uByte ->
                print(uByte.toString(16).padStart(2, '0'))
                if (arrayListOf(31, 63, 95, 127).contains(index)) {
                    println()
                }
            }
            counter++
        }
        println("Key stream and the end: ")
        keyStream.forEachIndexed { index, uByte ->
            print(uByte.toString(16))
            if (arrayListOf(31, 63, 95, 127).contains(index)) {
                println()
            }
        }
        val encoder = OneTimePad()

        return encoder.encodeAndDecode(dataByteArray, keyStream)
    }

}