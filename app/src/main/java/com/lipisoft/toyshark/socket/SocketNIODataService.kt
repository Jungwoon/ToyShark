package com.lipisoft.toyshark.socket

import android.util.Log

import com.lipisoft.toyshark.packet.ClientPacketWriter
import com.lipisoft.toyshark.session.Session
import com.lipisoft.toyshark.session.SessionManager
import com.lipisoft.toyshark.util.PacketUtil

import java.io.IOException
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit


class SocketNIODataService(private val clientPacketWriter: ClientPacketWriter) : Runnable {

    companion object {
        private val TAG = "SocketNIODataService"
        val syncSelector = Any()
        val syncSelector2 = Any()
    }

    @Volatile
    private var shutdown = false
    private var selector: Selector? = null

    // create thread pool for reading/writing data to socket
    // 스레드 풀을 만듦
    private val workerPool: ThreadPoolExecutor = ThreadPoolExecutor(
            8,
            100,
            10,
            TimeUnit.SECONDS,
            LinkedBlockingQueue()
    )

    override fun run() {
        Log.d(TAG, "SocketNIODataService starting in background...")
        selector = SessionManager.selector
        Log.d(TAG, "Selector is running...")

        while (!shutdown) {
            try {
                synchronized(syncSelector) {
                    selector!!.select() // Selector 구동, 최소한 하나의 채널이 작업 처리 준비가 될 때까지 블로킹
                }
            } catch (e: IOException) {
                Log.e(TAG, "Error in Selector.select(): " + e.message)
                Thread.sleep(100)
                continue
            }

            if (shutdown) break

            // selectedKeys()를 호출하여 선택된 키를 가져온다.
            synchronized(syncSelector2) {
                val iterator = selector!!.selectedKeys().iterator()

                while (iterator.hasNext()) {
                    val key = iterator.next()
                    val selectableChannel = key.channel()

                    try {
                        when (selectableChannel) {
                            is SocketChannel -> processTCPSelectionKey(key)
                            is DatagramChannel -> processUDPSelectionKey(key)
                        }
                    } catch (e: IOException) {
                        key.cancel()
                    }

                    iterator.remove()
                    if (shutdown) {
                        break
                    }
                }
            }
        }
    }

    /**
     * notify long running task to shutdown
     * @param shutdown to be shutdown or not
     */
    fun setShutdown(shutdown: Boolean) {
        this.shutdown = shutdown
        SessionManager.selector.wakeup()
    }

    @Throws(IOException::class)
    private fun processTCPSelectionKey(key: SelectionKey) {
        if (!key.isValid) {
            Log.d(TAG, "Invalid SelectionKey for TCP")
            return
        }

        val channel = key.channel() as SocketChannel
        val session = SessionManager.getSessionByChannel(channel) ?: return

        if (!session.isConnected && key.isConnectable) {
            val ip = PacketUtil.intToIPAddress(session.destIp)
            val port = session.destPort
            val address = InetSocketAddress(ip, port)
            Log.d(TAG, "connecting to remote tcp server: $ip:$port")

            var connected = false
            if (!channel.isConnected && !channel.isConnectionPending) {
                try {
                    connected = channel.connect(address) // 클라이언트쪽에서 서버로 연결
                } catch (e: Exception) {
                    Log.e(TAG, e.toString())
                    session.isAbortingConnection = true
                }
            }

            if (connected) {
                session.isConnected = connected
                Log.d(TAG, "connected immediately to remote tcp server: $ip:$port")
            } else {
                if (channel.isConnectionPending) {
                    connected = channel.finishConnect()
                    session.isConnected = connected
                    Log.d(TAG, "connected to remote tcp server: $ip:$port")
                }
            }
        }

        if (channel.isConnected) {
            processSelector(key, session)
        }
    }

    private fun processUDPSelectionKey(key: SelectionKey) {
        if (!key.isValid) {
            Log.d(TAG, "Invalid SelectionKey for UDP")
            return
        }

        var channel = key.channel() as DatagramChannel
        val session = SessionManager.getSessionByChannel(channel) ?: return

        if (!session.isConnected && key.isConnectable) {
            val ip = PacketUtil.intToIPAddress(session.destIp)
            val port = session.destPort
            val address = InetSocketAddress(ip, port)
            try {
                Log.d(TAG, "selector: connecting to remote UDP server: $ip:$port")
                channel = channel.connect(address)
                session.channel = channel
                session.isConnected = channel.isConnected
            } catch (e: Exception) {
                e.printStackTrace()
                session.isAbortingConnection = true
            }

        }
        if (channel.isConnected) {
            processSelector(key, session)
        }
    }

    private fun processSelector(selectionKey: SelectionKey, session: Session) {
        val sessionKey = SessionManager.createKey(
                session.destIp,
                session.destPort,
                session.sourceIp,
                session.sourcePort)

        // tcp has PSH flag when data is ready for sending, UDP does not have this
        if (selectionKey.isValid
                && selectionKey.isWritable
                && !session.isBusyWrite
                && session.hasDataToSend()
                && session.isDataForSendingReady) {

            session.isBusyWrite = true
            val worker = SocketDataWriterWorker(clientPacketWriter, sessionKey)
            workerPool.execute(worker)
        }

        if (selectionKey.isValid
                && selectionKey.isReadable
                && !session.isBusyRead) {

            session.isBusyRead = true
            val worker = SocketDataReaderWorker(clientPacketWriter, sessionKey)
            workerPool.execute(worker)
        }
    }
}
