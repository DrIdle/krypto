import krypto.hash.SHA1

@OptIn(ExperimentalUnsignedTypes::class)
fun main() {
    /*
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
     */

    /*

    var number: ULong = 4294967297u
    //print((number shl 32).toUInt().toString(2))
    println(number.toULong().toString(2))
    //number = number shr 1
    for (i in 0..32) {
        println("Shifting left by $i")
        println((number shl i).toULong().toString(2))
        println((number shl i).toULong().toString(2).length)
    }

    for (i in 0..32) {
        println("Shifting right by $i")
        println((number shr i).toULong().toString(2))
    }

    println()
    println("Breaking it into to 32bit integers")
    val numberLeft = number shr 32
    val numberRight = (number shl 32) shr 32
    println(numberLeft.toUInt())
    println(numberRight.toUInt())
    println("${numberLeft.toUInt().toString(2)}\t${numberRight.toUInt().toString(2)}")
    println(number.toString(2))
    //println((number shr 32).toUInt().toString(2))
    //println(number.toUInt())
    println("mod test")
    println(2528 % 512)
    println((2528 +(512-480+448)) % 512)

    println()
    println()

    var baseLength = 2528
    while(baseLength % 512 != 448) {
        baseLength += 8
    }
    println(baseLength)

    val testUInt = 4294967294u
    val testUByteArray = testUInt.toUByteArray()
    testUByteArray.forEach {
        println(it.toString(2))
    }
    println(testUByteArray.reversed().toUByteArray().toUInt())
    println()
    println(80u.toString(2).padStart(8,'0'))
    println(80u.toString(16))

    */
    val testString: String = "The quick brown fox jumps over the lazy dog"
    val uByteArray = testString.toByteArray(charset = Charsets.US_ASCII).toUByteArray()
    val sha1 = SHA1()
    val hash = sha1.hash(uByteArray)
    println(hash)
    println(hash.length)
    println("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
    println("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".length)

    val testString2: String = ""
    val uByteArray2 = testString2.toByteArray(charset = Charsets.US_ASCII).toUByteArray()
    val sha12 = SHA1()
    val hash2 = sha12.hash(uByteArray2)
    println(hash2)
    println(hash2.length)
    println("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    println("da39a3ee5e6b4b0d3255bfef95601890afd80709".length)

    for (i in 'A'..'Z') {
        val sha1Hasher = SHA1()
        val iString = i.toString()
        val newHash = sha1Hasher.hash(iString.toByteArray(charset = Charsets.US_ASCII).toUByteArray())
        println("Hashing \"$i\"\t hash: $newHash")
    }

    val testHasher = SHA1()
    val myhash = testHasher.hash(" ".toByteArray(Charsets.US_ASCII).toUByteArray())
    println(myhash)


}