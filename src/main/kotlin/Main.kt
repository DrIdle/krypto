import krypto.ciphers.stream_ciphers.Salsa20
import krypto.utils.strxor
import kotlin.experimental.xor

fun main(args: Array<String>) {
    
    println("Testing strxor function: ")
    val testString = "ABC"
    val testKey = "1+1"
    val charset = Charsets.US_ASCII
    val testStringByteArray = testString.toByteArray(charset = charset)
    val testKeyByteArray = testKey.toByteArray(charset = charset)
    val testResultByteArray = ByteArray(testString.length)
    for (index in testKey.indices){
        testResultByteArray[index] = testStringByteArray[index] xor testKeyByteArray[index]
    }
    println("Result should be: ${testResultByteArray.toString(charset = charset)}")
    println("Actual result: ${testString.strxor(testKey, charset)}")

    val salsaTestKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    val salsaNonce: Long = 1
    val salsaEncoder = Salsa20(salsaTestKey.toByteArray(charset = charset), salsaNonce)
    val encodedInformation = salsaEncoder.encodeAndDecode(testStringByteArray)
    println(encodedInformation.toString(charset = charset))
    val decodedInformation = salsaEncoder.encodeAndDecode(encodedInformation)
    println(decodedInformation.toString(charset = charset))

}