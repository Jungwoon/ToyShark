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
     * @param session Session
     */
    fun keepSessionAlive(session: Session) {
        val key = createKey(
                session.destIp,
                session.destPort,
                session.sourceIp,
                session.sourcePort)

        // 만들어진 키는 해쉬맵에 저장
        // key는 중복이 되지 않기 때문에 유일함
        concurrentHashMap[key] = session
    }

    /**
     * add data from client which will be sending to the destination server later one when receiving PSH flag.
     * PSH 플래그를 수신 할 때 나중에 대상 서버로 보낼 클라이언트의 데이터를 추가하십시오.
     * @param buffer  Data
     * @param session Data
     */
    fun addClientData(buffer: ByteBuffer, session: Session): Int {
        if (buffer.limit() <= buffer.position())
            return 0

        val payload = getRemainingBytes(buffer)

        // appending data to buffer
        session.setSendingData(payload)
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
     * 메모리에서 세션을 삭제하고 소켓 연결을 닫음
     * @param destIp      Destination IP Address
     * @param destPort    Destination Port
     * @param srcIp       Source IP Address
     * @param srcPort     Source Port
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

    /**
     * remove session from memory, then close socket connection.
     * 메모리에서 세션을 삭제하고 소켓 연결을 닫음
     */
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

    // 새로운 TCP 세션 생성
    fun createNewTCPSession(destIp: Int, destPort: Int, srcIp: Int, srcPort: Int): Session? {
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

        val socketChannel: SocketChannel

        try {
            socketChannel = SocketChannel.open()
            socketChannel.socket().keepAlive = true
            socketChannel.socket().tcpNoDelay = true
            socketChannel.socket().soTimeout = 0
            socketChannel.socket().receiveBufferSize = DataConst.MAX_RECEIVE_BUFFER_SIZE
            socketChannel.configureBlocking(false)
        } catch (e: SocketException) {
            Log.e(TAG, e.toString())
            return null
        } catch (e: IOException) {
            Log.e(TAG, "Failed to create SocketChannel: " + e.message)
            return null
        }

        val ip = PacketUtil.intToIPAddress(destIp)
        Log.d(TAG, "created new SocketChannel for $key")

        protector!!.protect(socketChannel.socket())

        Log.d(TAG, "Protected new SocketChannel")

        // initiate connection to reduce latency
        val socketAddress = InetSocketAddress(ip, destPort)
        Log.d(TAG, "initiate connecting to remote tcp server: $ip:$destPort")

        val connected: Boolean

        try {
            connected = socketChannel.connect(socketAddress)
        } catch (e: IOException) {
            Log.e(TAG, e.toString())
            return null
        }

        session.isConnected = connected

        // register for non-blocking operation
        // 논블록킹 처리
        try {
            synchronized(SocketNIODataService.syncSelector2) {
                selector!!.wakeup()
                synchronized(SocketNIODataService.syncSelector) {
                    val selectionKey = socketChannel.register(selector,
                            SelectionKey.OP_CONNECT or SelectionKey.OP_READ or SelectionKey.OP_WRITE)
                    session.selectionKey = selectionKey
                    Log.d(TAG, "Registered tcp selector successfully")
                }
            }
        } catch (e: ClosedChannelException) {
            e.printStackTrace()
            Log.e(TAG, "failed to register tcp channel with selector: " + e.message)
            return null
        }

        session.channel = socketChannel

        if (concurrentHashMap.containsKey(key)) {
            try {
                socketChannel.close()
            } catch (e: IOException) {
                e.printStackTrace()
            }

            return null
        } else {
            concurrentHashMap[key] = session
        }
        return session
    }

    // 새로운 UDP 세션 생성
    fun createNewUDPSession(destIp: Int, destPort: Int, srcIp: Int, srcPort: Int): Session? {
        val keys = createKey(
                destIp,
                destPort,
                srcIp,
                srcPort)

        if (concurrentHashMap.containsKey(keys))
            return concurrentHashMap[keys]

        val session = Session(srcIp, srcPort, destIp, destPort)

        val datagramChannel: DatagramChannel

        try {
            datagramChannel = DatagramChannel.open()
            datagramChannel.socket().soTimeout = 0
            datagramChannel.configureBlocking(false)

        } catch (e: IOException) {
            e.printStackTrace()
            return null
        }

        protector!!.protect(datagramChannel.socket())

        // initiate connection to reduce latency
        val ip = PacketUtil.intToIPAddress(destIp)
        val sourceIpAddress = PacketUtil.intToIPAddress(srcIp)
        val socketAddress = InetSocketAddress(ip, destPort)
        Log.d(TAG, "initialized connection to remote UDP server: " + ip + ":" +
                destPort + " from " + sourceIpAddress + ":" + srcPort)

        try {
            datagramChannel.connect(socketAddress)
            session.isConnected = datagramChannel.isConnected
        } catch (e: IOException) {
            e.printStackTrace()
            return null
        }

        try {
            synchronized(SocketNIODataService.syncSelector2) {
                selector!!.wakeup()
                synchronized(SocketNIODataService.syncSelector) {
                    val selectionKey: SelectionKey = if (datagramChannel.isConnected) {
                        datagramChannel.register(selector, SelectionKey.OP_READ or SelectionKey.OP_WRITE)
                    } else {
                        datagramChannel.register(selector, SelectionKey.OP_CONNECT or SelectionKey.OP_READ or
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

        session.channel = datagramChannel

        if (concurrentHashMap.containsKey(keys)) {
            try {
                datagramChannel.close()
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

    private fun getRemainingBytes(buffer: ByteBuffer): ByteArray {
        val length = buffer.limit() - buffer.position()
        val remainingBytes = ByteArray(length)

        for (i in 0 until length)
            remainingBytes[i] = buffer.get()

        return remainingBytes
    }
}
