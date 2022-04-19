import krypto.ciphers.stream_ciphers.Salsa20
import krypto.hash.MD5
import krypto.hash.SHA1

@OptIn(ExperimentalUnsignedTypes::class)
fun main() {
    /*val text = "ABC"
    val salsaTestKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    val salsaNonce: Long = 1
    val charset = Charsets.US_ASCII
    val salsaEncoder = Salsa20(salsaTestKey.toByteArray(charset = charset).toUByteArray(), salsaNonce)
    val encodedInformation = salsaEncoder.encodeAndDecode(text.toByteArray(charset = charset).toUByteArray())
    println("Length of key: ${salsaTestKey.toByteArray(charset = charset).toUByteArray().size}")
    println("Length of ciphertext: ${encodedInformation.size}")
    encodedInformation.forEach {
        print(it.toString(2).padStart(8, '0')+" ")
    }
    println()
    text.toByteArray(charset = charset).toUByteArray().forEach {
        print(it.toString(2).padStart(8, '0')+" ")
    }
    println()*/

    /*val nonceFirstPart = (salsaNonce shr 32).toUInt()
    val nonceSecondPart = ((salsaNonce shl 32) shr 32).toUInt()
    println(nonceFirstPart)
    println(nonceSecondPart)

    val keyArray = UByteArray(32)
    for (i in 1..32) {
        keyArray[i-1] = i.toUByte()
    }
    for (i in arrayListOf<Int>(3, 1, 4, 1, 5, 9, 2, 6)) {
        print(i.toUByte().toString(2).padStart(8, '0'))
    }
    println()
    val testNonce = 216458659516449286L
    val testEncoder = Salsa20(key = keyArray, nonce = testNonce)
    val cipherText = testEncoder.encodeAndDecode(text.toByteArray(charset = charset).toUByteArray(), startingPosition = 7L)
    testEncoder.initializeInternalState(keyArray, testNonce, 7L)
    println()
    testEncoder.internalState.forEachIndexed { index, uInt ->
        print("0x${uInt.toString(16).padStart(8, '0')} ")
        if (arrayListOf<Int>(3, 7, 11, 15).contains(index)) {
            println()
        }
    }

    val num1: UInt = 0x61707865u
    val num2: UInt = 0x58318d3eu

    val res: UInt = num1 + num2
    println("0x${res.toString(16).padStart(8,'0')}")*/

    val keyArray = UByteArray(32)
    keyArray[0] = 128.toUByte()
    for (i in 1..31) {
        keyArray[i] = 0.toUByte()
    }
    val textArray = UByteArray(64)
    for (i in 0 until 64) {
        textArray[i] = 65.toUByte()
    }
    val nonce: ULong = 0u
    val testEncoder = Salsa20(key = keyArray, nonce = nonce)
    //val ciphertext = testEncoder.encodeAndDecode(textArray)

    val md5 = MD5()
    val hash = md5.hash("They are deterministic".toByteArray(charset = Charsets.US_ASCII).toUByteArray())
    println()
    println(hash)



}