package krypto.ciphers.stream_ciphers

@OptIn(ExperimentalUnsignedTypes::class)
class OneTimePad {

    fun encodeAndDecode(informationByteArray: UByteArray, keyByteArray: UByteArray): UByteArray {
        if (informationByteArray.size != keyByteArray.size) {
            throw IllegalArgumentException("THe key must be as long as the information to be encoded")
        }
        return informationByteArray.zip(keyByteArray) {
            informationElement, keyElement ->
                informationElement xor keyElement
        }.toUByteArray()
    }
}