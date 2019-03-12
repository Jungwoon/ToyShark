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

package com.lipisoft.toyshark.session

import java.io.IOException
import java.nio.ByteBuffer
import com.lipisoft.toyshark.packet.ClientPacketWriter
import com.lipisoft.toyshark.packet.Packet
import com.lipisoft.toyshark.packet.PacketManager
import com.lipisoft.toyshark.network.ip.IPPacketFactory
import com.lipisoft.toyshark.network.ip.IPv4Header
import com.lipisoft.toyshark.socket.RawPacketQueue
import com.lipisoft.toyshark.util.PacketHeaderException
import com.lipisoft.toyshark.transport.tcp.TCPHeader
import com.lipisoft.toyshark.transport.tcp.TCPPacketFactory
import com.lipisoft.toyshark.transport.udp.UDPHeader
import com.lipisoft.toyshark.transport.udp.UDPPacketFactory
import com.lipisoft.toyshark.util.PacketUtil
import android.util.Log
import com.lipisoft.toyshark.util.DataConst.TCP
import com.lipisoft.toyshark.util.DataConst.UDP

/**
 * handle VPN client request and response. it create a new session for each VPN client.
 *
 * @author Borey Sao
 * Date: May 22, 2014
 */
object SessionHandler {
    private val TAG = "SessionHandler"
    private var writer: ClientPacketWriter? = null
    private val rawPacketQueue: RawPacketQueue = RawPacketQueue.instance

    fun setWriter(writer: ClientPacketWriter) {
        this.writer = writer
    }

    /**
     * VPN Client로부터 패킷이 들어왔을때, TCP, UDP 별로 처리
     * @param stream ByteBuffer to be read
     */
    @Throws(PacketHeaderException::class)
    fun handlePacket(stream: ByteBuffer) {
        val rawPacket = ByteArray(stream.limit())

        stream.get(rawPacket, 0, stream.limit())
        rawPacketQueue.addPacket(rawPacket)
        stream.rewind()

        // fileDescriptor 로부터 들어온 stream 을 IPv4 형태로 변환
        val ipHeader = IPPacketFactory.createIPv4Header(stream)

        // 위에서 변환된 ipHeader 가 tcp 인지 udp 인지 확인하는 부분
        val transportHeader = when {
            isTcpProtocol(ipHeader) -> TCPPacketFactory.createTCPHeader(stream)
            isUdpProtocol(ipHeader) -> UDPPacketFactory.createUDPHeader(stream)
            else -> return
        }

        val packet = Packet(ipHeader, transportHeader, stream.array())

        PacketManager.add(packet)
        PacketManager.handler.obtainMessage(PacketManager.PACKET).sendToTarget()

        // TCP 와 UDP 에 따라서 다르게 stream 을 처리함
        if (transportHeader is TCPHeader) {
            handleTCPPacket(stream, ipHeader, transportHeader)
        } else if (transportHeader is UDPHeader) {
            handleUDPPacket(stream, ipHeader, transportHeader)
        }
    }

    private fun handleTCPPacket(stream: ByteBuffer, ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        when {
            tcpHeader.isSYN -> createSessionAndReplySynAck(ipHeader, tcpHeader)
            tcpHeader.isACK -> processSession(ipHeader, tcpHeader, stream)
            tcpHeader.isFIN -> finishSession(ipHeader, tcpHeader)
            tcpHeader.isRST -> resetConnection(ipHeader, tcpHeader)
            else -> error(ipHeader, tcpHeader, stream)
        }
    }

    private fun createSessionAndReplySynAck(ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        ipHeader.identification = 0

        val packet = TCPPacketFactory.createSynAckPacketData(ipHeader, tcpHeader)
        val tcpPacket = packet.transportHeader as TCPHeader

        val session = SessionManager.createTCPSession(
                ipHeader.destinationIP,
                tcpHeader.destinationPort,
                ipHeader.sourceIP,
                tcpHeader.sourcePort
        ) ?: return

        val windowScaleFactor = Math.pow(2.0, tcpPacket.windowScale.toDouble()).toInt()
        session.setSendWindowSizeAndScale(tcpPacket.windowSize, windowScaleFactor)
        Log.d(TAG, "send-window size: " + session.sendWindow)

        session.maxSegmentSize = tcpPacket.maxSegmentSize
        session.sendUnAck = tcpPacket.sequenceNumber
        session.sendNext = tcpPacket.sequenceNumber + 1
        session.recSequence = tcpPacket.ackNumber // client initial sequence has been incremented by 1 and set to ack

        try {
            writer?.write(packet.buffer)
            rawPacketQueue.addPacket(packet.buffer)
            Log.d(TAG, "Send SYN-ACK to client")
        } catch (e: IOException) {
            Log.e(TAG, "Error sending data to client: " + e.message)
        }

    }

    private fun processSession(ipHeader: IPv4Header, tcpHeader: TCPHeader, stream: ByteBuffer) {
        val dataLength = stream.limit() - stream.position()

        val destIp = ipHeader.destinationIP
        val destPort = tcpHeader.destinationPort
        val srcIp = ipHeader.sourceIP
        val srcPort = tcpHeader.sourcePort

        // 키 형태: 111.1111.111.111:80-222.222.222.222:80
        val key = SessionManager.createKey(destIp, destPort, srcIp, srcPort)

        // {key: "111.1111.111.111:80-222.222.222.222:80", value: 세션}로 들어가있음
        val session = SessionManager.getSessionByKey(key)

        if (session == null) {
            if (tcpHeader.isFIN)
                sendLastAck(ipHeader, tcpHeader)
            else if (!tcpHeader.isRST)
                sendRst(ipHeader, tcpHeader, dataLength) // 강제 종료 패킷 전달

            return
        }

        session.lastIpHeader = ipHeader
        session.lastTcpHeader = tcpHeader

        if (hasClientData(dataLength)) {
            if (isNewDataAdded(session, tcpHeader)) {
                val addedLength = SessionManager.addClientData(stream, session)
                sendAck(ipHeader, tcpHeader, addedLength, session)
            } else {
                sendAckForDisorder(ipHeader, tcpHeader, dataLength)
            }
        } else {
            // an ack from client for previously sent data
            acceptAck(tcpHeader, session)

            if (session.isClosingConnection) {
                sendFinAck(ipHeader, tcpHeader, session) // 종료를 위해 FinAck를 보냄
            } else if (session.isAckToFin && !tcpHeader.isFIN) {
                // the last ACK from client after FIN-ACK flag was sent
                SessionManager.closeSession(destIp, destPort, srcIp, srcPort)
                Log.d(TAG, "got last ACK after FIN, session is now closed.")
            }
        }

        // received the last segment of data from vpn client
        when {
            tcpHeader.isPSH -> pushDataToDestination(session, tcpHeader)
            tcpHeader.isFIN -> replyFinAck(session, ipHeader, tcpHeader)
            tcpHeader.isRST -> resetConnection(ipHeader, tcpHeader)
        }

        if (!session.isClientWindowFull && !session.isAbortingConnection) {
            SessionManager.keepSessionAlive(session)
        }
    }

    private fun finishSession(ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        // case client sent FIN without ACK
        SessionManager.getSession(
                ipHeader.destinationIP,
                tcpHeader.destinationPort,
                ipHeader.sourceIP,
                tcpHeader.sourcePort
        ) ?.let {
            SessionManager.keepSessionAlive(it)
        } ?: replyFinAck(null, ipHeader, tcpHeader)

    }

    private fun resetConnection(ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        SessionManager.getSession(
                ipHeader.destinationIP,
                tcpHeader.destinationPort,
                ipHeader.sourceIP,
                tcpHeader.sourcePort
        ) ?.apply { isAbortingConnection = true }
    }

    private fun isTcpProtocol(ipHeader: IPv4Header) = ipHeader.protocol == TCP

    private fun isUdpProtocol(ipHeader: IPv4Header) = ipHeader.protocol == UDP

    private fun isNewDataAdded(session: Session, tcpHeader: TCPHeader) =
            session.recSequence == 0L || tcpHeader.sequenceNumber >= session.recSequence

    private fun error(ipHeader: IPv4Header, tcpHeader: TCPHeader, stream: ByteBuffer) {
        Log.d(TAG, "unknown TCP flag")
        val output = PacketUtil.getTCPOutput(ipHeader, tcpHeader, stream.array())
        Log.d(TAG, ">>>>>>>> Received from client <<<<<<<<<<")
        Log.d(TAG, output)
        Log.d(TAG, ">>>>>>>>>>>>>>>>>>>end receiving from client>>>>>>>>>>>>>>>>>>>>>")
    }

    private fun handleUDPPacket(
            streamByteBuffer: ByteBuffer,
            ipHeader: IPv4Header,
            udpHeader: UDPHeader
    ) {

        val session = SessionManager.getSession(
                ipHeader.destinationIP,
                udpHeader.destinationPort,
                ipHeader.sourceIP,
                udpHeader.sourcePort
        ) ?: SessionManager.createUDPSession(
                ipHeader.destinationIP,
                udpHeader.destinationPort,
                ipHeader.sourceIP,
                udpHeader.sourcePort
        ) ?: return

        session.lastIpHeader = ipHeader
        session.lastUdpHeader = udpHeader

        val length = SessionManager.addClientData(streamByteBuffer, session)
        session.isDataForSendingReady = true

        Log.d(TAG, "added UDP data for bg worker to send: $length")
        SessionManager.keepSessionAlive(session)
    }

    private fun sendRst(ipHeader: IPv4Header, tcpHeader: TCPHeader, dataLength: Int) {
        val data = TCPPacketFactory.createRstData(ipHeader, tcpHeader, dataLength)

        try {
            writer?.write(data)
            rawPacketQueue.addPacket(data)
            Log.d(TAG, "Sent RST Packet to client with dest => " +
                    PacketUtil.intToIPAddress(ipHeader.destinationIP) + ":" +
                    tcpHeader.destinationPort)
        } catch (e: IOException) {
            Log.e(TAG, "failed to send RST packet: " + e.message)
        }

    }

    private fun sendLastAck(ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        val data = TCPPacketFactory.createResponseAckData(
                ipHeader,
                tcpHeader,
                tcpHeader.sequenceNumber + 1
        )

        try {
            writer?.write(data)
            rawPacketQueue.addPacket(data)
            Log.d(TAG, "Sent last ACK Packet to client with dest => " +
                    PacketUtil.intToIPAddress(ipHeader.destinationIP) + ":" +
                    tcpHeader.destinationPort)
        } catch (e: IOException) {
            Log.e(TAG, "failed to send last ACK packet: " + e.message)
        }

    }

    private fun replyFinAck(session: Session?, ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        val ack = tcpHeader.sequenceNumber + 1
        val seq = tcpHeader.ackNumber
        val data = TCPPacketFactory.createFinAckData(
                ipHeader,
                tcpHeader,
                ack,
                seq,
                isFin = true,
                isAck = true
        )

        try {
            writer?.write(data)
            rawPacketQueue.addPacket(data)

            if (session != null) {
                session.selectionKey?.cancel()
                SessionManager.closeSession(session)
                Log.d(TAG, "ACK to client's FIN and close session => "
                        + PacketUtil.intToIPAddress(ipHeader.destinationIP)
                        + ":" + tcpHeader.destinationPort
                        + "-" + PacketUtil.intToIPAddress(ipHeader.sourceIP)
                        + ":" + tcpHeader.sourcePort)
            }
        } catch (e: IOException) {
            e.printStackTrace()
        }

    }

    private fun sendFinAck(ipHeader: IPv4Header, tcpHeader: TCPHeader, session: Session) {
        val ack = tcpHeader.sequenceNumber
        val seq = tcpHeader.ackNumber
        val data = TCPPacketFactory.createFinAckData(
                ipHeader,
                tcpHeader,
                ack,
                seq,
                isFin = true,
                isAck = false
        )

        val stream = ByteBuffer.wrap(data)

        try {
            writer?.write(data)
            rawPacketQueue.addPacket(data)

            Log.d(TAG, "00000000000 FIN-ACK packet data to vpn client 000000000000")

            var vpnIp: IPv4Header? = null

            try {
                vpnIp = IPPacketFactory.createIPv4Header(stream)
            } catch (e: PacketHeaderException) {
                e.printStackTrace()
            }

            var vpnTcp: TCPHeader? = null
            try {
                if (vpnIp != null)
                    vpnTcp = TCPPacketFactory.createTCPHeader(stream)
            } catch (e: PacketHeaderException) {
                e.printStackTrace()
            }

            if (vpnIp != null && vpnTcp != null) {
                val out = PacketUtil.getTCPOutput(vpnIp, vpnTcp, data)
                Log.d(TAG, out)
            }

            Log.d(TAG, "0000000000000 finished sending FIN-ACK packet to vpn client 000000000000")

        } catch (e: IOException) {
            Log.e(TAG, "Failed to send ACK packet: " + e.message)
        }

        session.sendNext = seq + 1
        // avoid re-sending it, from here client should take care the rest
        session.isClosingConnection = false
    }

    private fun pushDataToDestination(session: Session, tcp: TCPHeader) {
        session.isDataForSendingReady = true
        session.timestampReplyTo = tcp.timeStampSender
        session.timestampSender = System.currentTimeMillis().toInt()

        Log.d(TAG, "set data ready for sending to dest, bg will do it. data size: " + session.getSendingDataSize())
    }

    /**
     * send acknowledgment packet to VPN client
     */
    private fun sendAck(
            ipHeader: IPv4Header,
            tcpHeader: TCPHeader,
            acceptedDataLength: Int,
            session: Session
    ) {
        val ackNumber = session.recSequence + acceptedDataLength
        Log.d(TAG, "sent ack, ack# " + session.recSequence + " + " + acceptedDataLength + " = " + ackNumber)
        session.recSequence = ackNumber

        val data = TCPPacketFactory.createResponseAckData(ipHeader, tcpHeader, ackNumber)

        try {
            writer?.write(data)
            rawPacketQueue.addPacket(data)
        } catch (e: IOException) {
            Log.e(TAG, "Failed to send ACK packet: " + e.message)
        }
    }

    private fun sendAckForDisorder(
            ipHeader: IPv4Header,
            tcpHeader: TCPHeader,
            acceptedDataLength: Int
    ) {
        val ackNumber = tcpHeader.sequenceNumber + acceptedDataLength
        Log.d(TAG, "sent ack, ack# " + tcpHeader.sequenceNumber +
                " + " + acceptedDataLength + " = " + ackNumber)
        val data = TCPPacketFactory.createResponseAckData(ipHeader, tcpHeader, ackNumber)
        try {
            writer?.write(data)
            rawPacketQueue.addPacket(data)
        } catch (e: IOException) {
            Log.e(TAG, "Failed to send ACK packet: " + e.message)
        }

    }

    /**
     * acknowledge a packet and adjust the receiving window to avoid congestion.
     */
    private fun acceptAck(tcpHeader: TCPHeader, session: Session) {
        val isCorrupted = PacketUtil.isPacketCorrupted(tcpHeader)
        if (isCorrupted) {
            Log.e(TAG, "prev packet was corrupted, last ack# " + tcpHeader.ackNumber)
        }

        if (tcpHeader.ackNumber > session.sendUnAck || tcpHeader.ackNumber == session.sendNext) {
            session.isAck = true

            if (tcpHeader.windowSize > 0) {
                session.setSendWindowSizeAndScale(tcpHeader.windowSize, session.sendWindowScale)
            }

            session.sendUnAck = tcpHeader.ackNumber
            session.recSequence = tcpHeader.sequenceNumber
            session.timestampReplyTo = tcpHeader.timeStampSender
            session.timestampSender = System.currentTimeMillis().toInt()
        } else {
            Log.d(TAG, "Not Accepting ack# " + tcpHeader.ackNumber + " , it should be: " + session.sendNext)
            Log.d(TAG, "Prev sendUnack: " + session.sendUnAck)
            session.isAck = false
        }
    }

    private fun hasClientData(dataLength: Int) = dataLength > 0

}
