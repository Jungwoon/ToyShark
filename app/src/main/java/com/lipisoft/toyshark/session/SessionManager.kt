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

import android.util.Log

import com.lipisoft.toyshark.socket.DataConst
import com.lipisoft.toyshark.socket.SocketNIODataService
import com.lipisoft.toyshark.socket.SocketProtector
import com.lipisoft.toyshark.util.PacketUtil

import java.io.IOException
import java.net.InetSocketAddress
import java.net.SocketException
import java.nio.ByteBuffer
import java.nio.channels.ClosedChannelException
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.nio.channels.spi.AbstractSelectableChannel
import java.util.concurrent.ConcurrentHashMap

/**
 * Manage in-memory storage for VPN client session.
 *
 * @author Borey Sao
 * Date: May 20, 2014
 */
enum class SessionManager {
    INSTANCE;

    private val TAG = "SessionManager"
    private val concurrentHashMap = ConcurrentHashMap<String, Session>()
    private val protector = SocketProtector.getInstance()
    var selector: Selector? = null

    init {
        selector = Selector.open()
    }

    /**
     * keep java garbage collector from collecting a session
     *
     * @param session Session
     */
    fun keepSessionAlive(session: Session) {
        val key = createKey(
                session.destIp,
                session.destPort,
                session.sourceIp,
                session.sourcePort)

        concurrentHashMap[key] = session
    }

    private fun getRemainingBytes(buffer: ByteBuffer): ByteArray {
        val length = buffer.limit() - buffer.position()
        val remainingBytes = ByteArray(length)

        for (i in 0 until length)
            remainingBytes[i] = buffer.get()

        return remainingBytes
    }

    /**
     * add data from client which will be sending to the destination server later one when receiving PSH flag.
     *
     * @param buffer  Data
     * @param session Data
     */
    fun addClientData(buffer: ByteBuffer, session: Session): Int {
        if (buffer.limit() <= buffer.position())
            return 0
        val payload = getRemainingBytes(buffer)
        // appending data to buffer
        session.sendingData = payload
        return payload.size
    }

    fun getSession(destIp: Int, destPort: Int, srcIp: Int, srcPort: Int): Session? {
        val key = createKey(
                destIp,
                destPort,
                srcIp,
                srcPort)
        return getSessionByKey(key)
    }

    fun getSessionByKey(key: String): Session? {
        return if (concurrentHashMap.containsKey(key)) {
            concurrentHashMap[key]
        } else null

    }

    fun getSessionByChannel(channel: AbstractSelectableChannel): Session? {
        val sessions = concurrentHashMap.values
        for (session in sessions) {
            if (channel === session.channel)
                return session
        }

        return null
    }

    /**
     * remove session from memory, then close socket connection.
     *
     * @param destIp      Destination IP Address
     * @param destPort    Destination Port
     * @param srcIp   Source IP Address
     * @param srcPort Source Port
     */
    fun closeSession(destIp: Int, destPort: Int, srcIp: Int, srcPort: Int) {
        val key = createKey(
                destIp,
                destPort,
                srcIp,
                srcPort)
        val session = concurrentHashMap.remove(key)

        if (session != null) {
            val channel = session.channel
            try {
                channel?.close()
            } catch (e: IOException) {
                e.printStackTrace()
            }

            Log.d(TAG, "closed session -> $key")
        }
    }

    fun closeSession(session: Session) {
        val key = createKey(
                session.destIp,
                session.destPort,
                session.sourceIp,
                session.sourcePort)

        concurrentHashMap.remove(key)

        try {
            val channel = session.channel
            channel?.close()
        } catch (e: IOException) {
            Log.e(TAG, e.toString())
        }

        Log.d(TAG, "closed session -> $key")
    }

    fun createNewUDPSession(destIp: Int, destPort: Int, srcIp: Int, srcPort: Int): Session? {
        val keys = createKey(
                destIp,
                destPort,
                srcIp,
                srcPort)

        if (concurrentHashMap.containsKey(keys))
            return concurrentHashMap[keys]

        val session = Session(srcIp, srcPort, destIp, destPort)

        val channel: DatagramChannel

        try {
            channel = DatagramChannel.open()
            channel.socket().soTimeout = 0
            channel.configureBlocking(false)

        } catch (e: IOException) {
            e.printStackTrace()
            return null
        }

        protector!!.protect(channel.socket())

        // initiate connection to reduce latency
        val ips = PacketUtil.intToIPAddress(destIp)
        val sourceIpAddress = PacketUtil.intToIPAddress(srcIp)
        val socketAddress = InetSocketAddress(ips, destPort)
        Log.d(TAG, "initialized connection to remote UDP server: " + ips + ":" +
                destPort + " from " + sourceIpAddress + ":" + srcPort)

        try {
            channel.connect(socketAddress)
            session.isConnected = channel.isConnected
        } catch (e: IOException) {
            e.printStackTrace()
            return null
        }

        try {
            synchronized(SocketNIODataService.syncSelector2) {
                selector!!.wakeup()
                synchronized(SocketNIODataService.syncSelector) {
                    val selectionKey: SelectionKey
                    if (channel.isConnected) {
                        selectionKey = channel.register(selector, SelectionKey.OP_READ or SelectionKey.OP_WRITE)
                    } else {
                        selectionKey = channel.register(selector, SelectionKey.OP_CONNECT or SelectionKey.OP_READ or
                                SelectionKey.OP_WRITE)
                    }
                    session.selectionKey = selectionKey
                    Log.d(TAG, "Registered udp selector successfully")
                }
            }
        } catch (e: ClosedChannelException) {
            e.printStackTrace()
            Log.e(TAG, "failed to register udp channel with selector: " + e.message)
            return null
        }

        session.channel = channel

        if (concurrentHashMap.containsKey(keys)) {
            try {
                channel.close()
            } catch (e: IOException) {
                e.printStackTrace()
                return null
            }

        } else {
            concurrentHashMap[keys] = session
        }
        Log.d(TAG, "new UDP session successfully created.")
        return session
    }

    fun createNewSession(destIp: Int, destPort: Int, srcIp: Int, srcPort: Int): Session? {
        val key = createKey(
                destIp,
                destPort,
                srcIp,
                srcPort)

        if (concurrentHashMap.containsKey(key)) {
            Log.e(TAG, "Session was already created.")
            return null
        }

        val session = Session(srcIp, srcPort, destIp, destPort)

        val channel: SocketChannel

        try {
            channel = SocketChannel.open()
            channel.socket().keepAlive = true
            channel.socket().tcpNoDelay = true
            channel.socket().soTimeout = 0
            channel.socket().receiveBufferSize = DataConst.MAX_RECEIVE_BUFFER_SIZE
            channel.configureBlocking(false)

        } catch (e: SocketException) {
            Log.e(TAG, e.toString())
            return null
        } catch (e: IOException) {
            Log.e(TAG, "Failed to create SocketChannel: " + e.message)
            return null
        }

        val ips = PacketUtil.intToIPAddress(destIp)
        Log.d(TAG, "created new SocketChannel for $key")

        protector!!.protect(channel.socket())

        Log.d(TAG, "Protected new SocketChannel")

        // initiate connection to reduce latency
        val socketAddress = InetSocketAddress(ips, destPort)
        Log.d(TAG, "initiate connecting to remote tcp server: $ips:$destPort")
        val connected: Boolean
        try {
            connected = channel.connect(socketAddress)
        } catch (e: IOException) {
            Log.e(TAG, e.toString())
            return null
        }

        session.isConnected = connected

        // register for non-blocking operation
        try {
            synchronized(SocketNIODataService.syncSelector2) {
                selector!!.wakeup()
                synchronized(SocketNIODataService.syncSelector) {
                    val selectionKey = channel.register(selector,
                            SelectionKey.OP_CONNECT or SelectionKey.OP_READ or
                                    SelectionKey.OP_WRITE)
                    session.selectionKey = selectionKey
                    Log.d(TAG, "Registered tcp selector successfully")
                }
            }
        } catch (e: ClosedChannelException) {
            e.printStackTrace()
            Log.e(TAG, "failed to register tcp channel with selector: " + e.message)
            return null
        }

        session.channel = channel

        if (concurrentHashMap.containsKey(key)) {
            try {
                channel.close()
            } catch (e: IOException) {
                e.printStackTrace()
            }

            return null
        } else {
            concurrentHashMap[key] = session
        }
        return session
    }

    /**
     * create session key based on destination destIp+destPort and source destIp+destPort
     *
     * @param destIp      Destination IP Address
     * @param destPort    Destination Port
     * @param srcIp   Source IP Address
     * @param srcPort Source Port
     * @return String
     */
    fun createKey(destIp: Int, destPort: Int, srcIp: Int, srcPort: Int): String {
        return PacketUtil.intToIPAddress(srcIp) + ":" + srcPort + "-" +
                PacketUtil.intToIPAddress(destIp) + ":" + destPort
    }
}
