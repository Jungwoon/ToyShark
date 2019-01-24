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
import com.lipisoft.toyshark.Packet
import com.lipisoft.toyshark.PacketManager
import com.lipisoft.toyshark.network.ip.IPPacketFactory
import com.lipisoft.toyshark.network.ip.IPv4Header
import com.lipisoft.toyshark.socket.SocketData
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
    private val packetData: SocketData = SocketData.instance

    fun setWriter(writer: ClientPacketWriter) {
        this.writer = writer
    }

    private fun handleUDPPacket(clientPacketData: ByteBuffer, ipHeader: IPv4Header, udpheader: UDPHeader) {
        var session = SessionManager.INSTANCE.getSession(ipHeader.destinationIP, udpheader.destinationPort,
                ipHeader.sourceIP, udpheader.sourcePort)

        if (session == null) {
            session = SessionManager.INSTANCE.createNewUDPSession(ipHeader.destinationIP, udpheader.destinationPort,
                    ipHeader.sourceIP, udpheader.sourcePort)
        }

        if (session == null) {
            return
        }

        session.lastIpHeader = ipHeader
        session.lastUdpHeader = udpheader
        val len = SessionManager.INSTANCE.addClientData(clientPacketData, session)
        session.isDataForSendingReady = true
        Log.d(TAG, "added UDP data for bg worker to send: $len")
        SessionManager.INSTANCE.keepSessionAlive(session)
    }

    private fun handleTCPPacket(clientPacketData: ByteBuffer, ipHeader: IPv4Header, tcpheader: TCPHeader) {
        val dataLength = clientPacketData.limit() - clientPacketData.position()
        val sourceIP = ipHeader.sourceIP
        val destinationIP = ipHeader.destinationIP
        val sourcePort = tcpheader.sourcePort
        val destinationPort = tcpheader.destinationPort

        if (tcpheader.isSYN) {
            //3-way handshake + create new session
            //set windows size and scale, set reply time in options
            replySynAck(ipHeader, tcpheader)
        } else if (tcpheader.isACK) {
            val key = SessionManager.INSTANCE.createKey(destinationIP, destinationPort, sourceIP, sourcePort)
            val session = SessionManager.INSTANCE.getSessionByKey(key)

            if (session == null) {
                if (tcpheader.isFIN) {
                    sendLastAck(ipHeader, tcpheader)
                } else if (!tcpheader.isRST) {
                    sendRstPacket(ipHeader, tcpheader, dataLength)
                } else {
                    Log.e(TAG, "**** ==> Session not found: $key")
                }
                return
            }

            session.lastIpHeader = ipHeader
            session.lastTcpHeader = tcpheader

            //any data from client?
            if (dataLength > 0) {
                //accumulate data from client
                if (session.recSequence == 0L || tcpheader.sequenceNumber >= session.recSequence) {
                    val addedLength = SessionManager.INSTANCE.addClientData(clientPacketData, session)
                    //send ack to client only if new data was added
                    sendAck(ipHeader, tcpheader, addedLength, session)
                } else {
                    sendAckForDisorder(ipHeader, tcpheader, dataLength)
                }
            } else {
                //an ack from client for previously sent data
                acceptAck(tcpheader, session)

                if (session.isClosingConnection) {
                    sendFinAck(ipHeader, tcpheader, session)
                } else if (session.isAckToFin && !tcpheader.isFIN) {
                    //the last ACK from client after FIN-ACK flag was sent
                    SessionManager.INSTANCE.closeSession(destinationIP, destinationPort, sourceIP, sourcePort)
                    Log.d(TAG, "got last ACK after FIN, session is now closed.")
                }
            }
            //received the last segment of data from vpn client
            if (tcpheader.isPSH) {
                //push data to destination here. Background thread will receive data and fill session's buffer.
                //Background thread will send packet to client
                pushDataToDestination(session, tcpheader)
            } else if (tcpheader.isFIN) {
                //fin from vpn client is the last packet
                //ack it
                Log.d(TAG, "FIN from vpn client, will ack it.")
                ackFinAck(ipHeader, tcpheader, session)
            } else if (tcpheader.isRST) {
                resetConnection(ipHeader, tcpheader)
            }

            if (!session.isClientWindowFull && !session.isAbortingConnection) {
                SessionManager.INSTANCE.keepSessionAlive(session)
            }
        } else if (tcpheader.isFIN) {
            //case client sent FIN without ACK
            val session = SessionManager.INSTANCE.getSession(destinationIP, destinationPort, sourceIP, sourcePort)
            if (session == null)
                ackFinAck(ipHeader, tcpheader, null)
            else
                SessionManager.INSTANCE.keepSessionAlive(session)

        } else if (tcpheader.isRST) {
            resetConnection(ipHeader, tcpheader)
        } else {
            Log.d(TAG, "unknown TCP flag")
            val str1 = PacketUtil.getOutput(ipHeader, tcpheader, clientPacketData.array())
            Log.d(TAG, ">>>>>>>> Received from client <<<<<<<<<<")
            Log.d(TAG, str1)
            Log.d(TAG, ">>>>>>>>>>>>>>>>>>>end receiving from client>>>>>>>>>>>>>>>>>>>>>")
        }
    }

    /**
     * handle each packet from each vpn client
     *
     * @param stream ByteBuffer to be read
     */
    @Throws(PacketHeaderException::class)
    fun handlePacket(stream: ByteBuffer) {
        val rawPacket = ByteArray(stream.limit())
        stream.get(rawPacket, 0, stream.limit())
        packetData.addData(rawPacket)
        stream.rewind()

        val ipHeader = IPPacketFactory.createIPv4Header(stream)

        val transportHeader: ITransportHeader
        if (ipHeader.protocol.toInt() == 6) {
            transportHeader = TCPPacketFactory.createTCPHeader(stream)
        } else if (ipHeader.protocol.toInt() == 17) {
            transportHeader = UDPPacketFactory.createUDPHeader(stream)
        } else {
            Log.e(TAG, "******===> Unsupported protocol: " + ipHeader.protocol)
            return
        }

        val packet = Packet(ipHeader, transportHeader, stream.array())
        PacketManager.INSTANCE.add(packet)
        PacketManager.INSTANCE.handler.obtainMessage(PacketManager.PACKET).sendToTarget()

        if (transportHeader is TCPHeader) {
            handleTCPPacket(stream, ipHeader, transportHeader)
        } else if (ipHeader.protocol.toInt() == 17) {
            handleUDPPacket(stream, ipHeader, transportHeader as UDPHeader)
        }
    }

    private fun sendRstPacket(ip: IPv4Header, tcp: TCPHeader, dataLength: Int) {
        val data = TCPPacketFactory.createRstData(ip, tcp, dataLength)
        try {
            writer!!.write(data)
            packetData.addData(data)
            Log.d(TAG, "Sent RST Packet to client with dest => " +
                    PacketUtil.intToIPAddress(ip.destinationIP) + ":" +
                    tcp.destinationPort)
        } catch (e: IOException) {
            Log.e(TAG, "failed to send RST packet: " + e.message)
        }

    }

    private fun sendLastAck(ip: IPv4Header, tcp: TCPHeader) {
        val data = TCPPacketFactory.createResponseAckData(ip, tcp, tcp.sequenceNumber + 1)
        try {
            writer!!.write(data)
            packetData.addData(data)
            Log.d(TAG, "Sent last ACK Packet to client with dest => " +
                    PacketUtil.intToIPAddress(ip.destinationIP) + ":" +
                    tcp.destinationPort)
        } catch (e: IOException) {
            Log.e(TAG, "failed to send last ACK packet: " + e.message)
        }

    }

    private fun ackFinAck(ip: IPv4Header, tcp: TCPHeader, session: Session?) {
        val ack = tcp.sequenceNumber + 1
        val seq = tcp.ackNumber
        val data = TCPPacketFactory.createFinAckData(ip, tcp, ack, seq, true, true)
        try {
            writer!!.write(data)
            packetData.addData(data)
            if (session != null) {
                session.selectionKey.cancel()
                SessionManager.INSTANCE.closeSession(session)
                Log.d(TAG, "ACK to client's FIN and close session => " + PacketUtil.intToIPAddress(ip.destinationIP) + ":" + tcp.destinationPort
                        + "-" + PacketUtil.intToIPAddress(ip.sourceIP) + ":" + tcp.sourcePort)
            }
        } catch (e: IOException) {
            e.printStackTrace()
        }

    }

    private fun sendFinAck(ip: IPv4Header, tcp: TCPHeader, session: Session) {
        val ack = tcp.sequenceNumber
        val seq = tcp.ackNumber
        val data = TCPPacketFactory.createFinAckData(ip, tcp, ack, seq, true, false)
        val stream = ByteBuffer.wrap(data)
        try {
            writer!!.write(data)
            packetData.addData(data)
            Log.d(TAG, "00000000000 FIN-ACK packet data to vpn client 000000000000")
            var vpnip: IPv4Header? = null
            try {
                vpnip = IPPacketFactory.createIPv4Header(stream)
            } catch (e: PacketHeaderException) {
                e.printStackTrace()
            }

            var vpntcp: TCPHeader? = null
            try {
                if (vpnip != null)
                    vpntcp = TCPPacketFactory.createTCPHeader(stream)
            } catch (e: PacketHeaderException) {
                e.printStackTrace()
            }

            if (vpnip != null && vpntcp != null) {
                val sout = PacketUtil.getOutput(vpnip, vpntcp, data)
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

        Log.d(TAG, "set data ready for sending to dest, bg will do it. data size: " + session.sendingDataSize)
    }

    /**
     * send acknowledgment packet to VPN client
     *
     * @param ipheader           IP Header
     * @param tcpheader          TCP Header
     * @param acceptedDataLength Data Length
     * @param session            Session
     */
    private fun sendAck(ipheader: IPv4Header, tcpheader: TCPHeader, acceptedDataLength: Int, session: Session) {
        val acknumber = session.recSequence + acceptedDataLength
        Log.d(TAG, "sent ack, ack# " + session.recSequence + " + " + acceptedDataLength + " = " + acknumber)
        session.recSequence = acknumber
        val data = TCPPacketFactory.createResponseAckData(ipheader, tcpheader, acknumber)
        try {
            writer!!.write(data)
            packetData.addData(data)
        } catch (e: IOException) {
            Log.e(TAG, "Failed to send ACK packet: " + e.message)
        }

    }

    private fun sendAckForDisorder(ipHeader: IPv4Header, tcpheader: TCPHeader, acceptedDataLength: Int) {
        val ackNumber = tcpheader.sequenceNumber + acceptedDataLength
        Log.d(TAG, "sent ack, ack# " + tcpheader.sequenceNumber +
                " + " + acceptedDataLength + " = " + ackNumber)
        val data = TCPPacketFactory.createResponseAckData(ipHeader, tcpheader, ackNumber)
        try {
            writer!!.write(data)
            packetData.addData(data)
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
            //Log.d(TAG,"Accepted ack from client, ack# "+tcpheader.getAckNumber());

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
        }
    }

    /**
     * set connection as aborting so that background worker will close it.
     *
     * @param ip  IP
     * @param tcp TCP
     */
    private fun resetConnection(ip: IPv4Header, tcp: TCPHeader) {
        val session = SessionManager.INSTANCE.getSession(ip.destinationIP, tcp.destinationPort,
                ip.sourceIP, tcp.sourcePort)
        if (session != null) {
            session.isAbortingConnection = true
        }
    }

    /**
     * create a new client's session and SYN-ACK packet data to respond to client
     *
     * @param ip  IP
     * @param tcp TCP
     */
    private fun replySynAck(ip: IPv4Header, tcp: TCPHeader) {
        ip.identification = 0
        val packet = TCPPacketFactory.createSynAckPacketData(ip, tcp)

        val tcpheader = packet.transportHeader as TCPHeader

        val session = SessionManager.INSTANCE.createNewSession(ip.destinationIP,
                tcp.destinationPort, ip.sourceIP, tcp.sourcePort) ?: return

        val windowScaleFactor = Math.pow(2.0, tcpheader.windowScale.toDouble()).toInt()
        session.setSendWindowSizeAndScale(tcpheader.windowSize, windowScaleFactor)
        Log.d(TAG, "send-window size: " + session.sendWindow)
        session.maxSegmentSize = tcpheader.maxSegmentSize
        session.sendUnAck = tcpheader.sequenceNumber
        session.sendNext = tcpheader.sequenceNumber + 1
        //client initial sequence has been incremented by 1 and set to ack
        session.recSequence = tcpheader.ackNumber

        try {
            writer!!.write(packet.buffer)
            packetData.addData(packet.buffer)
            Log.d(TAG, "Send SYN-ACK to client")
        } catch (e: IOException) {
            Log.e(TAG, "Error sending data to client: " + e.message)
        }

    }

    companion object {
        private val TAG = "SessionHandler"

        val instance = SessionHandler()
    }
}
