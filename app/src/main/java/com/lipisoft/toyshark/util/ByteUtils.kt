package com.lipisoft.toyshark.util

import java.net.UnknownHostException

/**
 * Class for supporting byte level operations.
 * 1 .easy adding/getting numbers from
 * byte array at network order (AKA big-endian).
 * 2. printing methods (ordering bytes into readable hex format)
 * 3. transforming big-endian into little-endian and vice versa.
 * In general, java programming language is problematic in dealing with low level representation.
 * For example, no unsigned numbers. Therefore, in many cases we need to keep
 * number in a bigger storage, for example, uint_32 must be handled as long.
 * or else 0xFFFFFFFF will be treated as -1.
 *
 * @author roni bar-yanai
 */
object ByteUtils {

    private const val IPV4_ADDRESS_LEN = 4
    private const val MAX_PACKET_SIZE = 1600

    /**
     * turn 16 bits unsigned integer number to byte array representing the number
     * in network order.
     *
     * @param theNumber number to be changed to network stream
     * @return byte array
     * (int in java is 4 bytes here only the lower 2 bytes are counted)
     */
    fun getAsUInt16NetOrder(theNumber: Int): ByteArray {
        val toReturn = ByteArray(2)

        toReturn[0] = (theNumber and 0xf0).toByte()
        toReturn[1] = (theNumber and 0x0f).toByte()

        return toReturn
    }

    /**
     * turn 32 bits unsigned integer number to byte array representing the number
     * in network order.
     *
     * @param theNumber number to be changed to network stream
     * @return byte array
     */
    fun getAsUInt32NetOrder(theNumber: Int): ByteArray {
        val toReturn = ByteArray(4)

        toReturn[0] = (theNumber shr 24 and 0xff0).toByte()
        toReturn[1] = (theNumber shr 16 and 0xff).toByte()
        toReturn[2] = (theNumber shr 8 and 0xff).toByte()
        toReturn[3] = (theNumber and 0xff).toByte()

        return toReturn
    }

    /**
     * pull out a byte (unsigned) to int.
     *
     * @param theBytes - the byte array.
     * @param idx      - the byte location.
     * @return the int value (0-255)
     */
    fun getByteNetOrderToUInt8(theBytes: ByteArray, idx: Int): Int {
        return theBytes[idx].toInt() and 0xff
    }

    /**
     * pull out unsigned 16 bits integer out of the array.
     *
     * @param theBytes - the array
     * @param idx      - the starting index
     * @return the num (0-65535)
     */
    fun getByteNetOrderToUInt16(theBytes: ByteArray, idx: Int): Int {
        var sum = 0
        for (i in 0..1) {
            sum = (sum shl 8) + (0xff and theBytes[i + idx].toInt())
        }
        return sum
    }

    /**
     * pull out unsigned 16 bits integer out of the array.
     *
     * @param theBytes - the array
     * @param idx      - the starting index
     * @return the num (0-65535)
     */
    fun getByteLittleEndianUInt16(theBytes: ByteArray, idx: Int): Int {
        var sum = 0
        for (i in 0..1) {
            sum = (sum shl 8) + (0xff and theBytes[i + idx].toInt())
        }
        return flip16(sum)
    }

    /**
     * pull out unsigned 32 bits int out of the array.
     *
     * @param theBytes - the array
     * @param idx      - the starting index
     * @return the num
     */
    fun getByteNetOrderToUInt32(theBytes: ByteArray, idx: Int): Long {
        var sum: Long = 0
        for (i in 0..3) {
            sum = sum * 256 + (0xff and theBytes[i + idx].toInt())
        }
        return sum
    }

    /**
     * Limited to max of 8 bytes long
     *
     * @param theBytes
     * @param idx      index
     * @param size     size
     * @return signed long value.
     */
    fun getByteNetOrder(theBytes: ByteArray, idx: Int, size: Int): Long {
        var sum: Long = 0
        for (i in 0 until size) {
            sum = sum * 256 + (0xff and theBytes[i + idx].toInt())
        }
        return sum
    }

    /**
     * translate ip byte array to string
     *
     * @param theBytes   - the byte array
     * @param startIndex - the start idx
     * @return the ip as string
     * @throws UnknownHostException
     */
    @Throws(UnknownHostException::class)
    fun getAsIpv4AsString(theBytes: ByteArray?, startIndex: Int): String {
        if (theBytes == null || theBytes.size - startIndex > IPV4_ADDRESS_LEN)
            throw UnknownHostException()
        val toReturn = StringBuilder()
        for (i in 0 until IPV4_ADDRESS_LEN) {
            if (i != 0) {
                toReturn.append(".")
            }
            val field = 0xff and theBytes[i + startIndex].toInt()
            toReturn.append(field)
        }
        return toReturn.toString()
    }

    /**
     * turn ip in string representation to byte array in network order.
     *
     * @param ipAddress string type ip
     * @return ip as byte array
     * @throws UnknownHostException
     */
    @Throws(UnknownHostException::class)
    fun getIPV4NetworkOrder(ipAddress: String): ByteArray {
        val toReturn = ByteArray(IPV4_ADDRESS_LEN)

        val fields = ipAddress.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        if (fields.size < IPV4_ADDRESS_LEN)
            throw UnknownHostException()

        for (i in fields.indices) {
            toReturn[i] = Integer.parseInt(fields[i]).toByte()
        }
        return toReturn
    }

    /**
     * put number in array (big endian way)
     *
     * @param toPutIn    - the array to put in
     * @param startIndex - start index of the num
     * @param theNumber  - the number
     * @param len        - the number size in bytes.
     */
    fun setBigIndianInBytesArray(toPutIn: ByteArray, startIndex: Int, theNumber: Long, len: Int) {
        for (i in 0 until len) {
            val num = theNumber shr 8 * (len - (i + 1)) and 0xff
            toPutIn[i + startIndex] = num.toByte()
        }
    }

    /**
     * put number in array (big endian way)
     *
     * @param toPutIn    - the array to put in
     * @param startIndex - start index of the num
     * @param number  - the number
     * @param len        - the number size in bytes.
     */
    fun setLittleIndianInBytesArray(toPutIn: ByteArray, startIndex: Int, number: Long, len: Int) {
        var theNumber = number
        for (i in 0 until len) {
            toPutIn[i + startIndex] = (theNumber % 256).toByte()
            theNumber /= 256
        }
    }

    /**
     * copy byte array from array.
     *
     * @param from       - the original array
     * @param startIndex - the start index
     * @param length         - the length of the target array.
     * @return - the slice copied from the original array
     */
    fun extractBytesArray(from: ByteArray, startIndex: Int, length: Int): ByteArray {
        val toReturn = ByteArray(length)
        System.arraycopy(from, startIndex, toReturn, 0, toReturn.size)
        return toReturn
    }

    /**
     * for switching big/small endian
     *
     * @param num target number will be changed
     * @return flipped representation.
     */
    fun flip32(num: Long): Long {
        return (num and 0x000000FF shl 24) + (num and 0x0000FF00 shl 8) + (num and 0x00FF0000 shr 8) + (num and -0x1000000 shr 24)
    }

    /**
     * for switching big/small endian
     *
     * @param num target number will be changed
     * @return flipped representation.
     */
    private fun flip16(num: Int): Int {
        return (num and 0x00FF shl 8) + (num and 0xFF00 shr 8)
    }

    /**
     * The function change byte array order from little to big.
     *
     * @param data - the byte array to convert
     * @return converted byte array (not done in place).
     */
    fun convertLittleToBig(data: ByteArray): ByteArray {
        val toRet = ByteArray(data.size)
        for (i in data.indices) {
            toRet[i] = data[data.size - i - 1]
        }
        return toRet
    }

    private val statArr = CharArray(MAX_PACKET_SIZE * 10)

    /**
     * The method pull out array of bytes and return them as a
     * readable string in mac ip common format xx:xx:xx:xx:xx:xx
     *
     * @param theBytes - the packet
     * @param startIdx start index
     * @param endIdx   end index
     * @return the mas ip as string.
     */
    fun getAsMac(theBytes: ByteArray, startIdx: Int, endIdx: Int): String {
        var idx = 0
        for (i in startIdx until endIdx) {
            if (i > startIdx) {
                statArr[idx++] = ':'
            }
            val num = 0xff and theBytes[i].toInt()

            val second1 = num and 0x0f
            val first1 = num and 0xf0 shr 4

            val second = (if (second1 < 10) '0'.toInt() + second1 else 'A'.toInt() + second1 - 10).toChar()
            val first = (if (first1 < 10) '0'.toInt() + first1 else 'A'.toInt() + first1 - 10).toChar()

            statArr[idx++] = first
            statArr[idx++] = second
        }
        return String(statArr, 0, idx)
    }

    /**
     * covert byte array to string in a hex readable format
     *
     * @param thePacket packet stream
     * @return the byte array as string (in hex).
     */
    fun getAsString(thePacket: ByteArray): String {
        return getAsString(thePacket, 0, thePacket.size)
    }

    /**
     * covert byte array slice to string in a hex readable format
     *
     * @param thePacket  - the byte array.
     * @param startIndex - start index of the slice.
     * @param endIndex   - end index of the slice.
     * @return string
     */
    private fun getAsString(thePacket: ByteArray, startIndex: Int, endIndex: Int): String {
        return getAsString(thePacket, startIndex, endIndex, 16)
    }

    /**
     * covert byte array slice to string in a hex readable format
     *
     * @param thePacket - the byte array.
     * @param startIdx  - start index of the slice.
     * @param endIdx    - end index of the slice.
     * @param maxInLine - maximum chars per line
     * @return string
     */
    private fun getAsString(thePacket: ByteArray, startIdx: Int, endIdx: Int, maxInLine: Int): String {
        var idx = 0
        for (i in startIdx until endIdx) {
            if (i != 0 && i % 4 == 0) {
                statArr[idx++] = ' '
                statArr[idx++] = ' '
                statArr[idx++] = '-'
                statArr[idx++] = ' '
            }
            if (i != 0 && i % maxInLine == 0) {
                statArr[idx++] = '\r'
                statArr[idx++] = '\n'
            }

            val num = 0xff and thePacket[i].toInt()

            val second1 = num and 0x0f
            val first1 = num and 0xf0 shr 4

            val second = (if (second1 < 10) '0'.toInt() + second1 else 'A'.toInt() + second1 - 10).toChar()
            val first = (if (first1 < 10) '0'.toInt() + first1 else 'A'.toInt() + first1 - 10).toChar()

            statArr[idx++] = first
            statArr[idx++] = second
            statArr[idx++] = ' '
        }
        return String(statArr, 0, idx)
    }

}
