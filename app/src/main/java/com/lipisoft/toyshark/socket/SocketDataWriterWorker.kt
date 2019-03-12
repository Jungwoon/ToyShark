package com.lipisoft.toyshark.socket

import android.util.Log

import com.lipisoft.toyshark.packet.ClientPacketWriter
import com.lipisoft.toyshark.session.Session
import com.lipisoft.toyshark.session.SessionManager
import com.lipisoft.toyshark.transport.tcp.TCPPacketFactory
import com.lipisoft.toyshark.util.PacketUtil

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.NotYetConnectedException
import java.nio.channels.SocketChannel
import java.util.Date

class SocketDataWriterWorker(
        writer: ClientPacketWriter,
        private val sessionKey: String) : Runnable {

    companion object {
        private const val TAG = "SocketDataWriterWorker"
        private var writer: ClientPacketWriter? = null
    }

    init {
        SocketDataWriterWorker.writer = writer
    }

    override fun run() {
        val session = SessionManager.getSessionByKey(sessionKey)

        if (session == null) {
            Log.d(TAG, "No session related to $sessionKey for write")
            return
        }

        session.isBusyWrite = true

        val channel = session.channel

        when (channel) {
            is SocketChannel -> writeTCP(session)
            is DatagramChannel -> writeUDP(session)
            else -> return
        }

        session.isBusyWrite = false

        if (session.isAbortingConnection) {
            Log.d(TAG, "removing aborted connection -> $sessionKey")
            session.selectionKey!!.cancel()

            if (channel is SocketChannel) {
                try {
                    if (channel.isConnected) {
                        channel.close()
                    }
                } catch (e: IOException) {
                    e.printStackTrace()
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

            SessionManager.closeSession(session)
        }
    }

    private fun writeTCP(session: Session) {
        val channel = session.channel as SocketChannel
        val name = getName(session)

        val data = session.getSendingData()
        val buffer = ByteBuffer.allocate(data.size)
        buffer.put(data)
        buffer.flip()

        try {
            Log.d(TAG, "writing TCP data to: $name")
            Log.e("JW_TEST", "TCP Write : \n${String(buffer.array())}")
            channel.write(buffer)
        } catch (ex: NotYetConnectedException) {
            Log.e(TAG, "failed to write to unconnected socket: " + ex.message)
        } catch (e: IOException) {
            Log.e(TAG, "Error writing to server: " + e.message)

            // close connection with vpn client
            val rstData = TCPPacketFactory.createRstData(
                    session.lastIpHeader!!, session.lastTcpHeader!!, 0)
            try {
                writer!!.write(rstData)
                RawPacketQueue.instance.addPacket(rstData)
            } catch (ex: IOException) {
                ex.printStackTrace()
            }

            // remove session
            Log.e(TAG, "failed to write to remote socket, aborting connection")
            session.isAbortingConnection = true
        }

    }

    private fun writeUDP(session: Session) {
        if (!session.hasDataToSend()) {
            return
        }
        val channel = session.channel as DatagramChannel
        val name = getName(session)

        val data = session.getSendingData()
        val buffer = ByteBuffer.allocate(data.size)
        buffer.put(data)
        buffer.flip()

        try {
            val str = String(data)
            Log.d(TAG, "****** data write to server ********")
            Log.d(TAG, str)
            Log.d(TAG, "***** end writing to server *******")
            Log.d(TAG, "writing data to remote UDP: $name")
            channel.write(buffer)
            session.connectionStartTime = Date().time
        } catch (ex2: NotYetConnectedException) {
            session.isAbortingConnection = true
            Log.e(TAG, "Error writing to unconnected-UDP server, will abort current connection: " + ex2.message)
        } catch (e: IOException) {
            session.isAbortingConnection = true
            e.printStackTrace()
            Log.e(TAG, "Error writing to UDP server, will abort connection: " + e.message)
        }
    }

    private fun getName(session: Session): String {
        return  PacketUtil.intToIPAddress(session.destIp) + ":" + session.destPort +
                "-" + PacketUtil.intToIPAddress(session.sourceIp) + ":" + session.sourcePort
    }

}
