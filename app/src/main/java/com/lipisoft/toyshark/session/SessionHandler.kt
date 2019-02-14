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

import com.lipisoft.toyshark.ClientPacketWriter
import com.lipisoft.toyshark.packet.Packet
import com.lipisoft.toyshark.packet.PacketManager
import com.lipisoft.toyshark.network.ip.IPPacketFactory
import com.lipisoft.toyshark.network.ip.IPv4Header
import com.lipisoft.toyshark.socket.PacketQueue
import com.lipisoft.toyshark.transport.tcp.PacketHeaderException
import com.lipisoft.toyshark.transport.tcp.TCPHeader
import com.lipisoft.toyshark.transport.tcp.TCPPacketFactory
import com.lipisoft.toyshark.transport.ITransportHeader
import com.lipisoft.toyshark.transport.udp.UDPHeader
import com.lipisoft.toyshark.transport.udp.UDPPacketFactory
import com.lipisoft.toyshark.util.PacketUtil
import android.util.Log

/**
 * handle VPN client request and response. it create a new session for each VPN client.
 *
 * @author Borey Sao
 * Date: May 22, 2014
 */
class SessionHandler private constructor() {
    private var writer: ClientPacketWriter? = null
    private val packetQueue: PacketQueue = PacketQueue.instance

    companion object {
        private const val TAG = "SessionHandler"

        val instance = SessionHandler()
    }

    fun setWriter(writer: ClientPacketWriter) {
        this.writer = writer
    }

    /**
     * VPN Client로부터 패킷이 들어왔을때, TCP, UDP 별로 처리
     *
     * @param stream ByteBuffer to be read
     */
    @Throws(PacketHeaderException::class)
    fun handlePacket(stream: ByteBuffer) {
        val rawPacket = ByteArray(stream.limit())
        stream.get(rawPacket, 0, stream.limit())
        packetQueue.addData(rawPacket)
        stream.rewind()

        // fileDescriptor로부터 들어온 stream 을 IPv4 형태로 변환
        val ipHeader = IPPacketFactory.createIPv4Header(stream)
        val transportHeader: ITransportHeader

        val tcp = 6
        val udp = 17

        // 위에서 변환된 ipHeader가 tcp인지 udp인지 확인하는 부분
        when {
            ipHeader.protocol.toInt() == tcp -> transportHeader = TCPPacketFactory.createTCPHeader(stream)
            ipHeader.protocol.toInt() == udp -> transportHeader = UDPPacketFactory.createUDPHeader(stream)
            else -> {
                Log.e(TAG, "******===> Unsupported protocol: " + ipHeader.protocol)
                return
            }
        }

        // 위에서 받은 protocol 타입에 따라서 tcp 패킷이 될지, udp 패킷이 될지 정해짐
        val packet = Packet(ipHeader, transportHeader, stream.array())
        PacketManager.INSTANCE.add(packet)
        PacketManager.INSTANCE.handler.obtainMessage(PacketManager.PACKET).sendToTarget()

        // TCP 와 UDP 에 따라서 다르게 stream 을 처리함
        if (transportHeader is TCPHeader) {
            handleTCPPacket(stream, ipHeader, transportHeader)
        } else if (transportHeader is UDPHeader) {
            handleUDPPacket(stream, ipHeader, transportHeader)
        }
    }

    // 3-Way Handshake + create new session
    private fun handleTCPPacket(clientPacketData: ByteBuffer, ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        val dataLength = clientPacketData.limit() - clientPacketData.position()
        val sourceIP = ipHeader.sourceIP
        val destinationIP = ipHeader.destinationIP
        val sourcePort = tcpHeader.sourcePort
        val destinationPort = tcpHeader.destinationPort

        if (tcpHeader.isSYN) {
            // set windows size and scale, set reply time in options
            replySynAck(ipHeader, tcpHeader)
        }
        else if (tcpHeader.isACK) {
            val key = SessionManager.INSTANCE.createKey(destinationIP, destinationPort, sourceIP, sourcePort)
            val session = SessionManager.INSTANCE.getSessionByKey(key)

            if (session == null) {
                if (tcpHeader.isFIN) {
                    sendLastAck(ipHeader, tcpHeader)
                } else if (!tcpHeader.isRST) {
                    sendRstPacket(ipHeader, tcpHeader, dataLength)
                } else {
                    Log.e(TAG, "**** ==> Session not found: $key")
                }
                return
            }

            session.lastIpHeader = ipHeader
            session.lastTcpHeader = tcpHeader

            // any data from client?
            if (dataLength > 0) {
                // accumulate data from client
                if (session.recSequence == 0L || tcpHeader.sequenceNumber >= session.recSequence) {
                    val addedLength = SessionManager.INSTANCE.addClientData(clientPacketData, session)
                    // send ack to client only if new data was added
                    sendAck(ipHeader, tcpHeader, addedLength, session)
                } else {
                    sendAckForDisorder(ipHeader, tcpHeader, dataLength)
                }
            } else {
                // an ack from client for previously sent data
                acceptAck(tcpHeader, session)

                if (session.isClosingConnection) {
                    sendFinAck(ipHeader, tcpHeader, session)
                } else if (session.isAckToFin && !tcpHeader.isFIN) {
                    // the last ACK from client after FIN-ACK flag was sent
                    SessionManager.INSTANCE.closeSession(destinationIP, destinationPort, sourceIP, sourcePort)
                    Log.d(TAG, "got last ACK after FIN, session is now closed.")
                }
            }

            // received the last segment of data from vpn client
            when {
                // push data to destination here. Background thread will receive data and fill session's buffer.
                // Background thread will send packet to client
                tcpHeader.isPSH -> pushDataToDestination(session, tcpHeader)
                tcpHeader.isFIN -> ackFinAck(ipHeader, tcpHeader, session) // fin from vpn client is the last packet
                tcpHeader.isRST -> resetConnection(ipHeader, tcpHeader)
            }

            if (!session.isClientWindowFull && !session.isAbortingConnection) {
                SessionManager.INSTANCE.keepSessionAlive(session)
            }
        }
        else if (tcpHeader.isFIN) {
            // case client sent FIN without ACK
            val session = SessionManager.INSTANCE.getSession(destinationIP, destinationPort, sourceIP, sourcePort)
            if (session == null)
                ackFinAck(ipHeader, tcpHeader, null)
            else
                SessionManager.INSTANCE.keepSessionAlive(session)

        }
        else if (tcpHeader.isRST) {
            resetConnection(ipHeader, tcpHeader)
        }
        else {
            Log.d(TAG, "unknown TCP flag")
            val str1 = PacketUtil.getOutput(ipHeader, tcpHeader, clientPacketData.array())
            Log.d(TAG, ">>>>>>>> Received from client <<<<<<<<<<")
            Log.d(TAG, str1)
            Log.d(TAG, ">>>>>>>>>>>>>>>>>>>end receiving from client>>>>>>>>>>>>>>>>>>>>>")
        }
    }

    private fun handleUDPPacket(clientPacketData: ByteBuffer, ipHeader: IPv4Header, udpHeader: UDPHeader) {
        var session = SessionManager.INSTANCE.getSession(
                ipHeader.destinationIP,
                udpHeader.destinationPort,
                ipHeader.sourceIP,
                udpHeader.sourcePort)

        if (session == null) {
            session = SessionManager.INSTANCE.createNewUDPSession(
                    ipHeader.destinationIP,
                    udpHeader.destinationPort,
                    ipHeader.sourceIP,
                    udpHeader.sourcePort)
        }

        if (session == null) {
            return
        }

        session.lastIpHeader = ipHeader
        session.lastUdpHeader = udpHeader

        val length = SessionManager.INSTANCE.addClientData(clientPacketData, session)
        session.isDataForSendingReady = true
        Log.d(TAG, "added UDP data for bg worker to send: $length")
        SessionManager.INSTANCE.keepSessionAlive(session)
    }

    private fun sendRstPacket(ipHeader: IPv4Header, tcpHeader: TCPHeader, dataLength: Int) {
        val data = TCPPacketFactory.createRstData(ipHeader, tcpHeader, dataLength)
        try {
            writer!!.write(data)
            packetQueue.addData(data)
            Log.d(TAG, "Sent RST Packet to client with dest => " +
                    PacketUtil.intToIPAddress(ipHeader.destinationIP) + ":" +
                    tcpHeader.destinationPort)
        } catch (e: IOException) {
            Log.e(TAG, "failed to send RST packet: " + e.message)
        }

    }

    private fun sendLastAck(ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        val data = TCPPacketFactory.createResponseAckData(ipHeader, tcpHeader, tcpHeader.sequenceNumber + 1)
        try {
            writer!!.write(data)
            packetQueue.addData(data)
            Log.d(TAG, "Sent last ACK Packet to client with dest => " +
                    PacketUtil.intToIPAddress(ipHeader.destinationIP) + ":" +
                    tcpHeader.destinationPort)
        } catch (e: IOException) {
            Log.e(TAG, "failed to send last ACK packet: " + e.message)
        }

    }

    private fun ackFinAck(ipHeader: IPv4Header, tcpHeader: TCPHeader, session: Session?) {
        val ack = tcpHeader.sequenceNumber + 1
        val seq = tcpHeader.ackNumber
        val data = TCPPacketFactory.createFinAckData(ipHeader, tcpHeader, ack, seq, true, true)
        try {
            writer!!.write(data)
            packetQueue.addData(data)
            if (session != null) {
                session.selectionKey?.cancel()
                SessionManager.INSTANCE.closeSession(session)
                Log.d(TAG, "ACK to client's FIN and close session => " + PacketUtil.intToIPAddress(ipHeader.destinationIP) + ":" + tcpHeader.destinationPort
                        + "-" + PacketUtil.intToIPAddress(ipHeader.sourceIP) + ":" + tcpHeader.sourcePort)
            }
        } catch (e: IOException) {
            e.printStackTrace()
        }

    }

    private fun sendFinAck(ipHeader: IPv4Header, tcpHeader: TCPHeader, session: Session) {
        val ack = tcpHeader.sequenceNumber
        val seq = tcpHeader.ackNumber
        val data = TCPPacketFactory.createFinAckData(ipHeader, tcpHeader, ack, seq, true, false)
        val stream = ByteBuffer.wrap(data)
        try {
            writer!!.write(data)
            packetQueue.addData(data)
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
                val sout = PacketUtil.getOutput(vpnIp, vpnTcp, data)
                Log.d(TAG, sout)
            }
            Log.d(TAG, "0000000000000 finished sending FIN-ACK packet to vpn client 000000000000")

        } catch (e: IOException) {
            Log.e(TAG, "Failed to send ACK packet: " + e.message)
        }

        session.sendNext = seq + 1
        //avoid re-sending it, from here client should take care the rest
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
     *
     * @param ipHeader           IP Header
     * @param tcpHeader          TCP Header
     * @param acceptedDataLength Data Length
     * @param session            Session
     */
    private fun sendAck(ipHeader: IPv4Header, tcpHeader: TCPHeader, acceptedDataLength: Int, session: Session) {
        val ackNumber = session.recSequence + acceptedDataLength
        Log.d(TAG, "sent ack, ack# " + session.recSequence + " + " + acceptedDataLength + " = " + ackNumber)
        session.recSequence = ackNumber
        val data = TCPPacketFactory.createResponseAckData(ipHeader, tcpHeader, ackNumber)
        try {
            writer!!.write(data)
            packetQueue.addData(data)
        } catch (e: IOException) {
            Log.e(TAG, "Failed to send ACK packet: " + e.message)
        }

    }

    private fun sendAckForDisorder(ipHeader: IPv4Header, tcpHeader: TCPHeader, acceptedDataLength: Int) {
        val ackNumber = tcpHeader.sequenceNumber + acceptedDataLength
        Log.d(TAG, "sent ack, ack# " + tcpHeader.sequenceNumber +
                " + " + acceptedDataLength + " = " + ackNumber)
        val data = TCPPacketFactory.createResponseAckData(ipHeader, tcpHeader, ackNumber)
        try {
            writer!!.write(data)
            packetQueue.addData(data)
        } catch (e: IOException) {
            Log.e(TAG, "Failed to send ACK packet: " + e.message)
        }

    }

    /**
     * acknowledge a packet and adjust the receiving window to avoid congestion.
     *
     * @param tcpHeader TCP Header
     * @param session   Session
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

    /**
     * set connection as aborting so that background worker will close it.
     *
     * @param ipHeader  IP Header
     * @param tcpHeader TCP Header
     */
    private fun resetConnection(ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        val session = SessionManager.INSTANCE.getSession(ipHeader.destinationIP, tcpHeader.destinationPort,
                ipHeader.sourceIP, tcpHeader.sourcePort)
        if (session != null) {
            session.isAbortingConnection = true
        }
    }

    /**
     * create a new client's session and SYN-ACK packet data to respond to client
     *
     * @param ipHeader  IP Header
     * @param tcpHeader TCP Header
     */
    private fun replySynAck(ipHeader: IPv4Header, tcpHeader: TCPHeader) {
        ipHeader.identification = 0
        val packet = TCPPacketFactory.createSynAckPacketData(ipHeader, tcpHeader)

        val tcpPacket = packet.transportHeader as TCPHeader

        val session = SessionManager.INSTANCE.createNewTCPSession(ipHeader.destinationIP,
                tcpHeader.destinationPort, ipHeader.sourceIP, tcpHeader.sourcePort) ?: return

        val windowScaleFactor = Math.pow(2.0, tcpPacket.windowScale.toDouble()).toInt()
        session.setSendWindowSizeAndScale(tcpPacket.windowSize, windowScaleFactor)
        Log.d(TAG, "send-window size: " + session.sendWindow)
        session.maxSegmentSize = tcpPacket.maxSegmentSize
        session.sendUnAck = tcpPacket.sequenceNumber
        session.sendNext = tcpPacket.sequenceNumber + 1
        //client initial sequence has been incremented by 1 and set to ack
        session.recSequence = tcpPacket.ackNumber

        try {
            writer!!.write(packet.buffer)
            packetQueue.addData(packet.buffer)
            Log.d(TAG, "Send SYN-ACK to client")
        } catch (e: IOException) {
            Log.e(TAG, "Error sending data to client: " + e.message)
        }

    }

}
