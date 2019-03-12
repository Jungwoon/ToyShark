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

package com.lipisoft.toyshark.transport.tcp

import android.util.Log

import com.lipisoft.toyshark.packet.Packet
import com.lipisoft.toyshark.packet.PacketManager
import com.lipisoft.toyshark.network.ip.IPPacketFactory
import com.lipisoft.toyshark.network.ip.IPv4Header
import com.lipisoft.toyshark.util.PacketHeaderException
import com.lipisoft.toyshark.util.PacketUtil

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Date
import java.util.Random

/**
 * class to create IPv4 Header, TCP header, and packet data.
 *
 * @author Borey Sao
 * Date: May 8, 2014
 */
object TCPPacketFactory {
    val TAG = "TCPPacketFactory"

    private const val END_OF_OPTIONS_LIST = 0
    private const val NO_OPERATION = 1
    private const val MAX_SEGMENT_SIZE = 2
    private const val WINDOW_SCALE = 3
    private const val SELECTIVE_ACK_PERMITTED = 4
    private const val TIME_STAMP = 8

    private fun copyTCPHeader(tcpHeader: TCPHeader): TCPHeader {
        val tcp = TCPHeader(
                tcpHeader.sourcePort,
                tcpHeader.destinationPort,
                tcpHeader.sequenceNumber,
                tcpHeader.ackNumber,
                tcpHeader.dataOffset,
                tcpHeader.isNS,
                tcpHeader.tcpFlags,
                tcpHeader.windowSize,
                tcpHeader.checksum,
                tcpHeader.urgentPointer)

        tcp.maxSegmentSize = 65535
        tcp.windowScale = tcpHeader.windowScale
        tcp.isSelectiveAckPermitted = tcpHeader.isSelectiveAckPermitted
        tcp.timeStampSender = tcpHeader.timeStampSender
        tcp.timeStampReplyTo = tcpHeader.timeStampReplyTo
        return tcp
    }

    /**
     * create FIN-ACK for sending to client
     *
     * @param iPv4Header  IP Header
     * @param tcpHeader   TCP Header
     * @param ackToClient acknowledge
     * @param seqToClient sequence
     * @return byte[]
     */
    fun createFinAckData(
            iPv4Header: IPv4Header,
            tcpHeader: TCPHeader,
            ackToClient: Long,
            seqToClient: Long,
            isFin: Boolean,
            isAck: Boolean
    ): ByteArray {

        val ip = IPPacketFactory.copyIPv4Header(iPv4Header)
        val tcp = copyTCPHeader(tcpHeader)

        // flip IP from source to dest and vice-versa
        val sourceIp = ip.destinationIP
        val destIp = ip.sourceIP
        val sourcePort = tcp.destinationPort
        val destPort = tcp.sourcePort

        ip.destinationIP = destIp
        ip.sourceIP = sourceIp

        tcp.destinationPort = destPort
        tcp.sourcePort = sourcePort

        tcp.ackNumber = ackToClient
        tcp.sequenceNumber = seqToClient

        ip.identification = PacketUtil.getPacketId()

        // ACK
        tcp.setIsACK(isAck)
        tcp.setIsSYN(false)
        tcp.setIsPSH(false)
        tcp.setIsFIN(isFin)

        // set response timestamps in options fields
        tcp.timeStampReplyTo = tcp.timeStampSender
        val currentDate = Date()
        val senderTimestamp = currentDate.time.toInt()
        tcp.timeStampSender = senderTimestamp

        // recalculate IP length
        val totalLength = ip.ipHeaderLength + tcp.tcpHeaderLength

        ip.totalLength = totalLength

        return createPacketData(ip, tcp, null)
    }

    fun createFinData(
            ip: IPv4Header,
            tcp: TCPHeader,
            ackNumber: Long,
            seqNumber: Long,
            timeSender: Int,
            timeReplyTo: Int
    ): ByteArray {
        // flip IP from source to dest and vice-versa
        val sourceIp = ip.destinationIP
        val destIp = ip.sourceIP
        val sourcePort = tcp.destinationPort
        val destPort = tcp.sourcePort

        tcp.ackNumber = ackNumber
        tcp.sequenceNumber = seqNumber

        tcp.timeStampReplyTo = timeReplyTo
        tcp.timeStampSender = timeSender

        ip.destinationIP = destIp
        ip.sourceIP = sourceIp
        tcp.destinationPort = destPort
        tcp.sourcePort = sourcePort

        ip.identification = PacketUtil.getPacketId()

        tcp.setIsRST(false)
        tcp.setIsACK(true)
        tcp.setIsSYN(false)
        tcp.setIsPSH(false)
        tcp.setIsCWR(false)
        tcp.setIsECE(false)
        tcp.setIsFIN(true)
        tcp.isNS = false
        tcp.setIsURG(false)

        // remove any option field
        tcp.options = null

        // window size should be zero
        tcp.windowSize = 0

        // recalculate IP length
        val totalLength = ip.ipHeaderLength + tcp.tcpHeaderLength

        ip.totalLength = totalLength

        return createPacketData(ip, tcp, null)
    }

    /**
     * create packet with RST flag for sending to client when reset is required.
     *
     * @param ipHeader   IP Header
     * @param tcpHeader  TCP Header
     * @param dataLength Data Length
     * @return byte[]
     */
    fun createRstData(ipHeader: IPv4Header, tcpHeader: TCPHeader, dataLength: Int): ByteArray {
        val ip = IPPacketFactory.copyIPv4Header(ipHeader)
        val tcp = copyTCPHeader(tcpHeader)

        // flip IP from source to dest and vice-versa
        val sourceIp = ip.destinationIP
        val destIp = ip.sourceIP
        val sourcePort = tcp.destinationPort
        val destPort = tcp.sourcePort

        var ackNumber: Long = 0
        var seqNumber: Long = 0

        if (tcp.ackNumber > 0) {
            seqNumber = tcp.ackNumber
        } else {
            ackNumber = tcp.sequenceNumber + dataLength
        }
        tcp.ackNumber = ackNumber
        tcp.sequenceNumber = seqNumber

        ip.destinationIP = destIp
        ip.sourceIP = sourceIp
        tcp.destinationPort = destPort
        tcp.sourcePort = sourcePort

        ip.identification = 0

        tcp.setIsRST(true)
        tcp.setIsACK(false)
        tcp.setIsSYN(false)
        tcp.setIsPSH(false)
        tcp.setIsCWR(false)
        tcp.setIsECE(false)
        tcp.setIsFIN(false)
        tcp.isNS = false
        tcp.setIsURG(false)

        // remove any option field
        tcp.options = null

        // window size should be zero
        tcp.windowSize = 0

        // recalculate IP length
        val totalLength = ip.ipHeaderLength + tcp.tcpHeaderLength

        ip.totalLength = totalLength

        return createPacketData(ip, tcp, null)
    }

    /**
     * Acknowledgment to client that server has received request.
     *
     * @param ipHeader    IP Header
     * @param tcpHeader   TCP Header
     * @param ackToClient Acknowledge
     * @return byte[]
     */
    fun createResponseAckData(
            ipHeader: IPv4Header,
            tcpHeader: TCPHeader,
            ackToClient: Long
    ): ByteArray {
        val ip = IPPacketFactory.copyIPv4Header(ipHeader)
        val tcp = copyTCPHeader(tcpHeader)

        // flip IP from source to dest and vice-versa
        val sourceIp = ip.destinationIP
        val destIp = ip.sourceIP
        val sourcePort = tcp.destinationPort
        val destPort = tcp.sourcePort

        val seqNumber = tcp.ackNumber

        ip.destinationIP = destIp
        ip.sourceIP = sourceIp
        tcp.destinationPort = destPort
        tcp.sourcePort = sourcePort

        tcp.ackNumber = ackToClient
        tcp.sequenceNumber = seqNumber

        ip.identification = PacketUtil.getPacketId()

        // ACK
        tcp.setIsACK(true)
        tcp.setIsSYN(false)
        tcp.setIsPSH(false)
        tcp.setIsFIN(false)

        // set response timestamps in options fields
        tcp.timeStampReplyTo = tcp.timeStampSender
        val currentDate = Date()
        val senderTimestamp = currentDate.time.toInt()
        tcp.timeStampSender = senderTimestamp

        // recalculate IP length
        val totalLength = ip.ipHeaderLength + tcp.tcpHeaderLength

        ip.totalLength = totalLength

        return createPacketData(ip, tcp, null)
    }

    /**
     * create packet data for sending back to client
     *
     * @param ip         IP Header
     * @param tcp        TCP Header
     * @param packetData Packet Data
     * @return byte[]
     */
    fun createResponsePacketData(
            ip: IPv4Header,
            tcp: TCPHeader,
            packetData: ByteArray?,
            isPsh: Boolean,
            ackNumber: Long,
            seqNumber: Long,
            timeSender: Int,
            timeReplyto: Int
    ): ByteArray {
        val ipHeader = IPPacketFactory.copyIPv4Header(ip)
        val tcpHeader = copyTCPHeader(tcp)

        // flip IP from source to dest and vice-versa
        val sourceIp = ipHeader.destinationIP
        val sourcePort = tcpHeader.destinationPort
        ipHeader.destinationIP = ipHeader.sourceIP
        ipHeader.sourceIP = sourceIp
        tcpHeader.destinationPort = tcpHeader.sourcePort
        tcpHeader.sourcePort = sourcePort

        tcpHeader.ackNumber = ackNumber
        tcpHeader.sequenceNumber = seqNumber

        ipHeader.identification = PacketUtil.getPacketId()

        // ACK is always sent
        tcpHeader.setIsACK(true)
        tcpHeader.setIsSYN(false)
        tcpHeader.setIsPSH(isPsh)
        tcpHeader.setIsFIN(false)

        tcpHeader.timeStampSender = timeSender
        tcpHeader.timeStampReplyTo = timeReplyto

        // recalculate IP length
        var totalLength = ipHeader.ipHeaderLength + tcpHeader.tcpHeaderLength
        if (packetData != null) {
            totalLength += packetData.size
        }
        ipHeader.totalLength = totalLength

        return createPacketData(ipHeader, tcpHeader, packetData)
    }

    /**
     * create SYN-ACK packet data from writing back to client stream
     *
     * @param ip  IP Header
     * @param tcp TCP Header
     * @return class Packet
     */
    fun createSynAckPacketData(ip: IPv4Header, tcp: TCPHeader): Packet {
        val ipHeader = IPPacketFactory.copyIPv4Header(ip)
        val tcpHeader = copyTCPHeader(tcp)

        // flip IP from source to dest and vice-versa
        val sourceIp = ipHeader.destinationIP
        val destIp = ipHeader.sourceIP
        val sourcePort = tcpHeader.destinationPort
        val destPort = tcpHeader.sourcePort
        val ackNumber = tcpHeader.sequenceNumber + 1
        var seqNumber: Long
        val random = Random()
        seqNumber = random.nextInt().toLong()
        if (seqNumber < 0) {
            seqNumber *= -1
        }
        ipHeader.destinationIP = destIp
        ipHeader.sourceIP = sourceIp
        tcpHeader.destinationPort = destPort
        tcpHeader.sourcePort = sourcePort

        // ack = received sequence + 1
        tcpHeader.ackNumber = ackNumber

        // initial sequence number generated by server
        tcpHeader.sequenceNumber = seqNumber
        Log.d(TAG, "Set Initial Sequence number: $seqNumber")

        // SYN-ACK
        tcpHeader.setIsACK(true)
        tcpHeader.setIsSYN(true)

        // timestamp in options fields
        tcpHeader.timeStampReplyTo = tcpHeader.timeStampSender
        val currentDate = Date()
        val senderTimestamp = currentDate.time.toInt()
        tcpHeader.timeStampSender = senderTimestamp

        return Packet(ipHeader, tcpHeader, createPacketData(ipHeader, tcpHeader, null))
    }

    /**
     * create packet data from IP Header, TCP header and data
     *
     * @param ipHeader  IPv4Header object
     * @param tcpHeader TCPHeader object
     * @param data      array of byte (packet body)
     * @return array of byte
     */
    private fun createPacketData(
            ipHeader: IPv4Header,
            tcpHeader: TCPHeader,
            data: ByteArray?
    ): ByteArray {

        var dataLength = 0
        if (data != null) {
            dataLength = data.size
        }
        val buffer = ByteArray(ipHeader.ipHeaderLength + tcpHeader.tcpHeaderLength + dataLength)
        val ipBuffer = IPPacketFactory.createIPv4HeaderData(ipHeader)
        val tcpBuffer = createTCPHeaderData(tcpHeader)

        System.arraycopy(ipBuffer, 0, buffer, 0, ipBuffer.size)
        System.arraycopy(tcpBuffer, 0, buffer, ipBuffer.size, tcpBuffer.size)
        if (dataLength > 0) {
            val offset = ipBuffer.size + tcpBuffer.size
            System.arraycopy(data!!, 0, buffer, offset, dataLength)
        }

        // calculate checksum for both IP and TCP header
        val zero = byteArrayOf(0, 0)

        // zero out checksum first before calculation
        System.arraycopy(zero, 0, buffer, 10, 2)
        val ipChecksum = PacketUtil.calculateChecksum(buffer, 0, ipBuffer.size)

        // write result of checksum back to buffer
        System.arraycopy(ipChecksum, 0, buffer, 10, 2)

        // zero out TCP header checksum first
        val tcpStart = ipBuffer.size
        System.arraycopy(zero, 0, buffer, tcpStart + 16, 2)
        val tcpChecksum = PacketUtil.calculateTCPHeaderChecksum(
                buffer,
                tcpStart,
                tcpBuffer.size + dataLength,
                ipHeader.destinationIP,
                ipHeader.sourceIP
        )

        // write new checksum back to array
        System.arraycopy(tcpChecksum, 0, buffer, tcpStart + 16, 2)

        PacketManager.add(Packet(ipHeader, tcpHeader, buffer))
        PacketManager.handler.obtainMessage(PacketManager.PACKET).sendToTarget()

        return buffer
    }

    /**
     * create array of byte from a given TCPHeader object
     *
     * @param header instance of TCPHeader
     * @return array of byte
     */
    private fun createTCPHeaderData(header: TCPHeader): ByteArray {
        val buffer = ByteArray(header.tcpHeaderLength)
        buffer[0] = (header.sourcePort shr 8).toByte()
        buffer[1] = header.sourcePort.toByte()
        buffer[2] = (header.destinationPort shr 8).toByte()
        buffer[3] = header.destinationPort.toByte()

        val sequenceNumber = ByteBuffer.allocate(4)
        sequenceNumber.order(ByteOrder.BIG_ENDIAN)
        sequenceNumber.putInt(header.sequenceNumber.toInt())

        // sequence number
        System.arraycopy(sequenceNumber.array(), 0, buffer, 4, 4)

        val ackNumber = ByteBuffer.allocate(4)
        ackNumber.order(ByteOrder.BIG_ENDIAN)
        ackNumber.putInt(header.ackNumber.toInt())
        System.arraycopy(ackNumber.array(), 0, buffer, 8, 4)

        buffer[12] = (if (header.isNS)
            header.dataOffset shl 4 or 0x1
        else
            header.dataOffset shl 4).toByte()
        buffer[13] = header.tcpFlags.toByte()

        buffer[14] = (header.windowSize shr 8).toByte()
        buffer[15] = header.windowSize.toByte()

        buffer[16] = (header.checksum shr 8).toByte()
        buffer[17] = header.checksum.toByte()

        buffer[18] = (header.urgentPointer shr 8).toByte()
        buffer[19] = header.urgentPointer.toByte()

        // set timestamp for both sender and reply to
        val options = header.options
        if (options != null) {
            var i = 0
            while (i < options.size) {
                val kind = options[i]
                if (kind > 1) {
                    if (kind.toInt() == 8) {
                        i += 2
                        if (i + 7 < options.size) {
                            PacketUtil.writeIntToBytes(header.timeStampSender, options, i)
                            i += 4
                            PacketUtil.writeIntToBytes(header.timeStampReplyTo, options, i)
                        }
                        break
                    } else if (i + 1 < options.size) {
                        val len = options[i + 1]
                        i = i + len - 1
                    }
                }
                i++
            }
            if (options.isNotEmpty()) {
                System.arraycopy(options, 0, buffer, 20, options.size)
            }
        }

        return buffer
    }

    /**
     * create a TCP Header from a given byte array
     *
     * @param stream array of byte
     * @return a new instance of TCPHeader
     * @throws PacketHeaderException throws PacketHeaderException
     */
    @Throws(PacketHeaderException::class)
    fun createTCPHeader(stream: ByteBuffer): TCPHeader {

        if (stream.remaining() < 20) {
            throw PacketHeaderException("There is not enough space for TCP header from provided starting position")
        }

        val sourcePort = stream.short.toInt() and 0xFFFF
        val destPort = stream.short.toInt() and 0xFFFF
        val sequenceNumber = stream.int.toLong()
        val ackNumber = stream.int.toLong()
        val dataOffsetAndNs = stream.get().toInt()

        val dataOffset = dataOffsetAndNs and 0xF0 shr 4
        if (stream.remaining() < (dataOffset - 5) * 4) {
            throw PacketHeaderException("invalid array size for TCP header from given starting position")
        }

        val isNs = dataOffsetAndNs and 0x1 > 0x0
        val tcpFlag = stream.get().toInt()
        val windowSize = stream.short.toInt()
        val checksum = stream.short.toInt()
        val urgentPointer = stream.short.toInt()

        val header = TCPHeader(
                sourcePort,
                destPort,
                sequenceNumber,
                ackNumber,
                dataOffset,
                isNs,
                tcpFlag,
                windowSize,
                checksum,
                urgentPointer
        )

        if (dataOffset > 5) {
            handleTcpOptions(header, stream, dataOffset * 4 - 20)
        }

        return header
    }

    private fun handleTcpOptions(header: TCPHeader, packet: ByteBuffer, optionsSize: Int) {
        var index = 0

        while (index < optionsSize) {
            val optionKind = packet.get()
            index++

            if (optionKind.toInt() == END_OF_OPTIONS_LIST || optionKind.toInt() == NO_OPERATION) {
                continue
            }

            val size = packet.get()
            index++

            when (optionKind.toInt()) {
                MAX_SEGMENT_SIZE -> {
                    header.maxSegmentSize = packet.short.toInt()
                    index += 2
                }
                WINDOW_SCALE -> {
                    header.windowScale = packet.get().toInt()
                    index++
                }
                SELECTIVE_ACK_PERMITTED -> header.isSelectiveAckPermitted = true
                TIME_STAMP -> {
                    header.timeStampSender = packet.int
                    header.timeStampReplyTo = packet.int
                    index += 8
                }
                else -> {
                    skipRemainingOptions(packet, size.toInt())
                    index = index + size - 2
                }
            }
        }
    }

    private fun skipRemainingOptions(packet: ByteBuffer, size: Int) {
        for (i in 2 until size) {
            packet.get()
        }
    }
}
