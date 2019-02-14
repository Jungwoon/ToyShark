package com.lipisoft.toyshark.socket

import android.util.Log

import com.lipisoft.toyshark.ClientPacketWriter
import com.lipisoft.toyshark.session.Session
import com.lipisoft.toyshark.session.SessionManager
import com.lipisoft.toyshark.network.ip.IPPacketFactory
import com.lipisoft.toyshark.packetRebuild.PCapFileWriter
import com.lipisoft.toyshark.transport.tcp.PacketHeaderException
import com.lipisoft.toyshark.transport.tcp.TCPPacketFactory
import com.lipisoft.toyshark.transport.udp.UDPPacketFactory
import com.lipisoft.toyshark.util.PacketUtil

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.ClosedByInterruptException
import java.nio.channels.ClosedChannelException
import java.nio.channels.DatagramChannel
import java.nio.channels.NotYetConnectedException
import java.nio.channels.SocketChannel
import java.util.Date

/**
 * background task for reading data from remote server and write data to vpn client
 *
 * @author Borey Sao
 * Date: July 30, 2014
 */
internal class SocketDataReaderWorker(private val writer: ClientPacketWriter, private val sessionKey: String) : Runnable {
    private val packetQueue: PacketQueue = PacketQueue.instance

    companion object {
        private const val TAG = "SocketDataReaderWorker"
    }

    override fun run() {
        val session = SessionManager.INSTANCE.getSessionByKey(sessionKey)
        if (session == null) {
            Log.e(TAG, "Session NOT FOUND")
            return
        }

        val channel = session.channel

        when (channel) {
            is SocketChannel -> readTCP(session)
            is DatagramChannel -> readUDP(session)
            else -> return
        }

        if (session.isAbortingConnection) {
            Log.d(TAG, "removing aborted connection -> $sessionKey")
            session.selectionKey!!.cancel()
            if (channel is SocketChannel) {
                try {
                    if (channel.isConnected) {
                        channel.close()
                    }
                } catch (e: IOException) {
                    Log.e(TAG, e.toString())
                }

            } else {
                try {
                    val datagramChannel = channel as DatagramChannel
                    if (datagramChannel.isConnected) {
                        datagramChannel.close()
                    }
                } catch (e: IOException) {
                    e.printStackTrace()
                }

            }
            SessionManager.INSTANCE.closeSession(session)
        } else {
            session.isBusyRead = false
        }
    }

    private fun readTCP(session: Session) {
        if (session.isAbortingConnection) {
            return
        }

        val channel = session.channel as SocketChannel
        val buffer = ByteBuffer.allocate(DataConst.MAX_RECEIVE_BUFFER_SIZE)
        var len: Int

        try {
            do {
                if (!session.isClientWindowFull) {
                    len = channel.read(buffer)
                    if (len > 0) {
                        // -1 mean it reach the end of stream
                        sendToRequester(buffer, len, session)
                        buffer.clear()
                    } else if (len == -1) {
                        Log.d(TAG, "End of data from remote server, will send FIN to client")
                        Log.d(TAG, "send FIN to: $sessionKey")
                        sendFin(session)
                        session.isAbortingConnection = true
                    }
                } else {
                    Log.e(TAG, "*** client window is full, now pause for $sessionKey")
                    break
                }
            } while (len > 0)
        } catch (e: NotYetConnectedException) {
            Log.e(TAG, "socket not connected")
        } catch (e: ClosedByInterruptException) {
            Log.e(TAG, "ClosedByInterruptException reading SocketChannel: " + e.message)
            //session.setAbortingConnection(true);
        } catch (e: ClosedChannelException) {
            Log.e(TAG, "ClosedChannelException reading SocketChannel: " + e.message)
            //session.setAbortingConnection(true);
        } catch (e: IOException) {
            Log.e(TAG, "Error reading data from SocketChannel: " + e.message)
            session.isAbortingConnection = true
        }

    }

    private fun sendToRequester(buffer: ByteBuffer, dataSize: Int, session: Session) {
        //last piece of data is usually smaller than MAX_RECEIVE_BUFFER_SIZE
        session.hasReceivedLastSegment = dataSize < DataConst.MAX_RECEIVE_BUFFER_SIZE

        buffer.limit(dataSize)
        buffer.flip()
        // TODO should allocate new byte array?
        val data = ByteArray(dataSize)
        System.arraycopy(buffer.array(), 0, data, 0, dataSize)
        session.addReceivedData(data)

        // pushing all data to vpn client
        while (session.hasReceivedData()) {
            pushDataToClient(session)
        }
    }

    /**
     * create packet data and send it to VPN client
     *
     * @param session Session
     */
    private fun pushDataToClient(session: Session) {
        if (!session.hasReceivedData()) {
            // no data to send
            Log.d(TAG, "no data for vpn client")
        }

        val ipHeader = session.lastIpHeader!!
        val tcpheader = session.lastTcpHeader!!
        // TODO What does 60 mean?
        var max = session.maxSegmentSize - 60

        if (max < 1) {
            max = 1024
        } else if (max > PCapFileWriter.MAX_PACKET_SIZE - 60) {
            max = PCapFileWriter.MAX_PACKET_SIZE - 60
        }
        val packetBody = session.getReceivedData(max)
        if (packetBody.isNotEmpty()) {
            val unAck = session.sendNext
            val nextUnAck = session.sendNext + packetBody.size
            session.sendNext = nextUnAck

            val data = TCPPacketFactory.createResponsePacketData(ipHeader,
                    tcpheader, packetBody, session.hasReceivedLastSegment,
                    session.recSequence, unAck,
                    session.timestampSender, session.timestampReplyTo)
            try {
                writer.write(data)
                packetQueue.addData(data)
            } catch (e: IOException) {
                Log.e(TAG, "Failed to send ACK + Data packet: " + e.message)
            }

        }
    }

    private fun sendFin(session: Session) {
        val ipHeader = session.lastIpHeader!!
        val tcpHeader = session.lastTcpHeader!!
        val data = TCPPacketFactory.createFinData(ipHeader, tcpHeader,
                session.sendNext, session.recSequence,
                session.timestampSender, session.timestampReplyTo)
        try {
            writer.write(data)
            packetQueue.addData(data)
        } catch (e: IOException) {
            Log.e(TAG, "Failed to send FIN packet: " + e.message)
        }

    }

    private fun readUDP(session: Session) {
        val channel = session.channel as DatagramChannel
        val buffer = ByteBuffer.allocate(DataConst.MAX_RECEIVE_BUFFER_SIZE)
        var len: Int

        try {
            do {
                if (session.isAbortingConnection) {
                    break
                }
                len = channel.read(buffer)
                if (len > 0) {
                    val date = Date()
                    val responseTime = date.time - session.connectionStartTime

                    buffer.limit(len)
                    buffer.flip()
                    //create UDP packet
                    val data = ByteArray(len)
                    System.arraycopy(buffer.array(), 0, data, 0, len)
                    val packetData = UDPPacketFactory.createResponsePacket(
                            session.lastIpHeader!!, session.lastUdpHeader!!, data)
                    //write to client
                    writer.write(packetData)
                    //publish to packet subscriber
                    packetQueue.addData(packetData)
                    Log.d(TAG, "SDR: sent " + len + " bytes to UDP client, packetData.length: "
                            + packetData.size)
                    buffer.clear()

                    try {
                        val stream = ByteBuffer.wrap(packetData)
                        val ip = IPPacketFactory.createIPv4Header(stream)
                        val udp = UDPPacketFactory.createUDPHeader(stream)
                        val str = PacketUtil.getUDPOutput(ip, udp)
                        Log.d(TAG, "++++++ SD: packet sending to client ++++++++")
                        Log.i(TAG, "got response time: $responseTime")
                        Log.d(TAG, str)
                        Log.d(TAG, "++++++ SD: end sending packet to client ++++")
                    } catch (e: PacketHeaderException) {
                        e.printStackTrace()
                    }

                }
            } while (len > 0)
        } catch (ex: NotYetConnectedException) {
            Log.e(TAG, "failed to read from unconnected UDP socket")
        } catch (e: IOException) {
            e.printStackTrace()
            Log.e(TAG, "Failed to read from UDP socket, aborting connection")
            session.isAbortingConnection = true
        }

    }
}
