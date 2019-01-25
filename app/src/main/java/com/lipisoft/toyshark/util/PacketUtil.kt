/*
 *  Copyright 2014 AT&T
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.lipisoft.toyshark.util

import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.SocketException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import android.util.Log

import com.lipisoft.toyshark.network.ip.IPv4Header
import com.lipisoft.toyshark.transport.tcp.TCPHeader
import com.lipisoft.toyshark.transport.udp.UDPHeader
import kotlin.experimental.and
import kotlin.experimental.or


/**
 * Helper class to perform various useful task
 *
 * @author Borey Sao
 * Date: May 8, 2014
 */
object PacketUtil {
    private val TAG = "PacketUtil"

    @Volatile
    private var packetId = 0

    /**
     * get IP address of device
     *
     * @return IP Address
     */
    val localIpAddress: String?
        get() {
            try {
                val en = NetworkInterface.getNetworkInterfaces()
                while (en.hasMoreElements()) {
                    val networkInterface = en.nextElement()
                    if (networkInterface.displayName != "tun0") {
                        val addresses = networkInterface.inetAddresses
                        while (addresses.hasMoreElements()) {
                            val inetAddress = addresses.nextElement()
                            if (!inetAddress.isLoopbackAddress && inetAddress is Inet4Address)
                                return inetAddress.getHostAddress()
                        }
                    }
                }
            } catch (ex: SocketException) {
                ex.printStackTrace()
            }

            return null
        }

    @Synchronized
    fun getPacketId(): Int {
        return packetId++
    }

    /**
     * convert int to byte array
     * https://docs.oracle.com/javase/tutorial/java/nutsandbolts/datatypes.html
     *
     * @param value  int value 32 bits
     * @param buffer array of byte to write to
     * @param offset position to write to
     */
    fun writeIntToBytes(value: Int, buffer: ByteArray, offset: Int) {
        if (buffer.size - offset < 4) {
            return
        }
        buffer[offset] = (value.ushr(24) and 0x000000FF).toByte()
        buffer[offset + 1] = (value shr 16 and 0x000000FF).toByte()
        buffer[offset + 2] = (value shr 8 and 0x000000FF).toByte()
        buffer[offset + 3] = (value and 0x000000FF).toByte()
    }

    /**
     * convert short to byte array
     *
     * @param value  short value to convert
     * @param buffer array of byte to put value to
     * @param offset starting position in array
     */
    fun writeShortToBytes(value: Short, buffer: ByteArray, offset: Int) {
        if (buffer.size - offset < 2) {
            return
        }
        buffer[offset] = ((value.toInt() ushr 8) and 0x00FF).toByte()
        buffer[offset + 1] = (value and 0x00FF).toByte()
    }

    /**
     * extract short value from a byte array using Big Endian byte order
     *
     * @param buffer array of byte
     * @param start  position to start extracting value
     * @return value of short
     */
    fun getNetworkShort(buffer: ByteArray, start: Int): Short {
        var value: Short = 0x0000
        value = value or (buffer[start].toInt() and 0xFF).toShort()
        value = (value.toInt() shl 8).toShort()
        value = value or (buffer[start + 1].toInt() and 0xFF).toShort()
        return value
    }

    /**
     * convert array of max 4 bytes to int
     *
     * @param buffer byte array
     * @param start  Starting point to be read in byte array
     * @param length Length to be read
     * @return value of int
     */
    fun getNetworkInt(buffer: ByteArray, start: Int, length: Int): Int {
        var value = 0
        var end = start + if (length > 4) 4 else length

        if (end > buffer.size)
            end = buffer.size

        for (i in start until end) {
            value = value or (buffer[i].toInt() and 0xFF)
            if (i < end - 1)
                value = value shl 8
        }

        return value
    }

    /**
     * convert array of max 4 bytes to long
     *
     * @param buffer byte array
     * @param start  Starting point to be read in byte array
     * @param length Length to be read
     * @return value of long
     */
    fun getNetworkLong(buffer: ByteArray, start: Int, length: Int): Long {
        var value: Long = 0
        var end = start + if (length > 4) 4 else length

        if (end > buffer.size)
            end = buffer.size

        for (i in start until end) {
            value = value or (buffer[i].toInt() and 0xFF).toLong()
            if (i < end - 1)
                value = value shl 8
        }

        return value
    }

    /**
     * validate TCP header checksum
     *
     * @param source      Source Port
     * @param destination Destination Port
     * @param data        Payload
     * @param tcpLength   TCP Header length
     * @param tcpOffset
     * @return boolean
     */
    fun isValidTCPChecksum(source: Int, destination: Int,
                           data: ByteArray, tcpLength: Short, tcpOffset: Int): Boolean {
        var buffersize = tcpLength + 12
        var isodd = false
        if (buffersize % 2 != 0) {
            buffersize++
            isodd = true
        }

        val buffer = ByteBuffer.allocate(buffersize)
        buffer.putInt(source)
        buffer.putInt(destination)
        buffer.put(0.toByte())//reserved => 0
        buffer.put(6.toByte())//TCP protocol => 6
        buffer.putShort(tcpLength)
        buffer.put(data, tcpOffset, tcpLength.toInt())
        if (isodd) {
            buffer.put(0.toByte())
        }
        return isValidIPChecksum(buffer.array(), buffersize)
    }

    /**
     * validate IP Header checksum
     *
     * @param data   byte stream
     * @param length
     * @return boolean
     */
    private fun isValidIPChecksum(data: ByteArray, length: Int): Boolean {
        var start = 0
        var sum = 0
        while (start < length) {
            sum += getNetworkInt(data, start, 2)
            start = start + 2
        }

        //carry over one's complement
        while (sum shr 16 > 0)
            sum = (sum and 0xffff) + (sum shr 16)

        //flip the bit to get one' complement
        sum = sum.inv()
        val buffer = ByteBuffer.allocate(4)
        buffer.putInt(sum)

        return buffer.getShort(2).toInt() == 0
    }

    fun calculateChecksum(data: ByteArray, offset: Int, length: Int): ByteArray {
        var start = offset
        var sum = 0
        while (start < length) {
            sum += PacketUtil.getNetworkInt(data, start, 2)
            start = start + 2
        }
        //carry over one's complement
        while (sum shr 16 > 0) {
            sum = (sum and 0xffff) + (sum shr 16)
        }
        //flip the bit to get one' complement
        sum = sum.inv()

        //extract the last two byte of int
        val checksum = ByteArray(2)
        checksum[0] = (sum shr 8).toByte()
        checksum[1] = sum.toByte()

        return checksum
    }

    fun calculateTCPHeaderChecksum(data: ByteArray, offset: Int, tcplength: Int, destip: Int, sourceip: Int): ByteArray {
        var buffersize = tcplength + 12
        var odd = false
        if (buffersize % 2 != 0) {
            buffersize++
            odd = true
        }
        val buffer = ByteBuffer.allocate(buffersize)
        buffer.order(ByteOrder.BIG_ENDIAN)

        //create virtual header
        buffer.putInt(sourceip)
        buffer.putInt(destip)
        buffer.put(0.toByte())//reserved => 0
        buffer.put(6.toByte())//tcp protocol => 6
        buffer.putShort(tcplength.toShort())

        //add actual header + data
        buffer.put(data, offset, tcplength)

        //padding last byte to zero
        if (odd) {
            buffer.put(0.toByte())
        }
        val tcparray = buffer.array()
        return calculateChecksum(tcparray, 0, buffersize)
    }

    fun intToIPAddress(addressInt: Int): String {
        return (addressInt.ushr(24) and 0x000000FF).toString() + "." +
                (addressInt.ushr(16) and 0x000000FF).toString() + "." +
                (addressInt.ushr(8) and 0x000000FF).toString() + "." +
                (addressInt and 0x000000FF).toString()
    }

    fun getUDPOutput(ipheader: IPv4Header, udp: UDPHeader): String {
        return "\r\nIP Version: " + ipheader.ipVersion +
                "\r\nProtocol: " + ipheader.protocol +
                "\r\nID# " + ipheader.identification +
                "\r\nIP Total Length: " + ipheader.totalLength +
                "\r\nIP Header length: " + ipheader.ipHeaderLength +
                "\r\nIP checksum: " + ipheader.headerChecksum +
                "\r\nMay fragement? " + ipheader.isMayFragment +
                "\r\nLast fragment? " + ipheader.lastFragment +
                "\r\nFlag: " + ipheader.flag +
                "\r\nFragment Offset: " + ipheader.fragmentOffset +
                "\r\nDest: " + intToIPAddress(ipheader.destinationIP) +
                ":" + udp.destinationPort +
                "\r\nSrc: " + intToIPAddress(ipheader.sourceIP) +
                ":" + udp.sourcePort +
                "\r\nUDP Length: " + udp.length +
                "\r\nUDP Checksum: " + udp.checksum
    }

    fun getOutput(ipHeader: IPv4Header, tcpheader: TCPHeader,
                  packetData: ByteArray): String {
        val tcpLength = (packetData.size - ipHeader.ipHeaderLength).toShort()
        val isValidChecksum = PacketUtil.isValidTCPChecksum(
                ipHeader.sourceIP, ipHeader.destinationIP,
                packetData, tcpLength, ipHeader.ipHeaderLength)
        val isValidIPChecksum = PacketUtil.isValidIPChecksum(packetData,
                ipHeader.ipHeaderLength)
        val packetBodyLength = (packetData.size - ipHeader.ipHeaderLength
                - tcpheader.tcpHeaderLength)

        val str = StringBuilder("\r\nIP Version: ")
                .append(ipHeader.ipVersion.toInt())
                .append("\r\nProtocol: ").append(ipHeader.protocol.toInt())
                .append("\r\nID# ").append(ipHeader.identification)
                .append("\r\nTotal Length: ").append(ipHeader.totalLength)
                .append("\r\nData Length: ").append(packetBodyLength)
                .append("\r\nDest: ").append(intToIPAddress(ipHeader.destinationIP))
                .append(":").append(tcpheader.destinationPort)
                .append("\r\nSrc: ").append(intToIPAddress(ipHeader.sourceIP))
                .append(":").append(tcpheader.sourcePort)
                .append("\r\nACK: ").append(tcpheader.ackNumber)
                .append("\r\nSeq: ").append(tcpheader.sequenceNumber)
                .append("\r\nIP Header length: ").append(ipHeader.ipHeaderLength)
                .append("\r\nTCP Header length: ").append(tcpheader.tcpHeaderLength)
                .append("\r\nACK: ").append(tcpheader.isACK)
                .append("\r\nSYN: ").append(tcpheader.isSYN)
                .append("\r\nCWR: ").append(tcpheader.isCWR)
                .append("\r\nECE: ").append(tcpheader.isECE)
                .append("\r\nFIN: ").append(tcpheader.isFIN)
                .append("\r\nNS: ").append(tcpheader.isNS)
                .append("\r\nPSH: ").append(tcpheader.isPSH)
                .append("\r\nRST: ").append(tcpheader.isRST)
                .append("\r\nURG: ").append(tcpheader.isURG)
                .append("\r\nIP checksum: ").append(ipHeader.headerChecksum)
                .append("\r\nIs Valid IP Checksum: ").append(isValidIPChecksum)
                .append("\r\nTCP Checksum: ").append(tcpheader.checksum)
                .append("\r\nIs Valid TCP checksum: ").append(isValidChecksum)
                .append("\r\nMay fragement? ").append(ipHeader.isMayFragment)
                .append("\r\nLast fragment? ").append(ipHeader.lastFragment)
                .append("\r\nFlag: ").append(ipHeader.flag.toInt())
                .append("\r\nFragment Offset: ").append(ipHeader.fragmentOffset.toInt())
                .append("\r\nWindow: ").append(tcpheader.windowSize)
                .append("\r\nWindow scale: ").append(tcpheader.windowScale)
                .append("\r\nData Offset: ").append(tcpheader.dataOffset)

        val options = tcpheader.options
        if (options != null) {
            str.append("\r\nTCP Options: \r\n..........")
            var i = 0
            while (i < options.size) {
                val kind = options[i]
                if (kind.toInt() == 0) {
                    str.append("\r\n...End of options packetList")
                } else if (kind.toInt() == 1) {
                    str.append("\r\n...NOP")
                } else if (kind.toInt() == 2) {
                    i += 2
                    val maxSegmentSize = PacketUtil.getNetworkInt(options, i, 2)
                    i++
                    str.append("\r\n...Max Seg Size: ").append(maxSegmentSize)
                } else if (kind.toInt() == 3) {
                    i += 2
                    val windowSize = PacketUtil.getNetworkInt(options, i, 1)
                    str.append("\r\n...Window Scale: ").append(windowSize)
                } else if (kind.toInt() == 4) {
                    i++
                    str.append("\r\n...Selective Ack")
                } else if (kind.toInt() == 5) {
                    i = i + options[++i] - 2
                    str.append("\r\n...selective ACK (SACK)")
                } else if (kind.toInt() == 8) {
                    i += 2
                    val timeStampValue = PacketUtil.getNetworkInt(options, i, 4)
                    i += 4
                    val timeStampEchoReply = PacketUtil.getNetworkInt(options, i, 4)
                    i += 3
                    str.append("\r\n...Timestamp: ").append(timeStampValue)
                            .append("-").append(timeStampEchoReply)
                } else if (kind.toInt() == 14) {
                    i += 2
                    str.append("\r\n...Alternative Checksum request")
                } else if (kind.toInt() == 15) {
                    i = i + options[++i] - 2
                    str.append("\r\n...TCP Alternate Checksum Data")
                } else {
                    str.append("\r\n... unknown option# ").append(kind.toInt())
                            .append(", int: ").append(kind.toInt())
                }
                i++
            }
        }
        return str.toString()
    }

    /**
     * detect packet corruption flag in tcp options sent from client ACK
     *
     * @param tcpHeader TCPHeader
     * @return boolean
     */
    fun isPacketCorrupted(tcpHeader: TCPHeader): Boolean {
        val options = tcpHeader.options

        if (options != null) {
            var i = 0
            while (i < options.size) {
                val kind = options[i]

                if (kind.toInt() == 0 || kind.toInt() == 1) {
                } else if (kind.toInt() == 2) {
                    i += 3
                } else if (kind.toInt() == 3 || kind.toInt() == 14) {
                    i += 2
                } else if (kind.toInt() == 4) {
                    i++
                } else if (kind.toInt() == 5 || kind.toInt() == 15) {
                    i = i + options[++i] - 2
                } else if (kind.toInt() == 8) {
                    i += 9
                } else if (kind.toInt() == 23) {
                    return true
                } else {
                    Log.e(TAG, "unknown option: $kind")
                }
                i++
            }
        }
        return false
    }

    fun bytesToStringArray(bytes: ByteArray): String {
        val str = StringBuilder("{ ")

        for (i in bytes.indices) {
            if (i == 0)
                str.append(bytes[i].toInt())
            else
                str.append(", ").append(bytes[i].toInt())
        }
        str.append(" }")

        return str.toString()
    }
}
