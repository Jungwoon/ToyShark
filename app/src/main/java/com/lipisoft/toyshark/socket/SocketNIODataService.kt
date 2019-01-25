package com.lipisoft.toyshark.socket

import android.util.Log

import com.lipisoft.toyshark.ClientPacketWriter
import com.lipisoft.toyshark.session.Session
import com.lipisoft.toyshark.session.SessionManager
import com.lipisoft.toyshark.util.PacketUtil

import java.io.IOException
import java.net.InetSocketAddress
import java.nio.channels.ClosedChannelException
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.nio.channels.UnresolvedAddressException
import java.nio.channels.UnsupportedAddressTypeException
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
    private val workerPool: ThreadPoolExecutor = ThreadPoolExecutor(
            8,
            100,
            10,
            TimeUnit.SECONDS, LinkedBlockingQueue())

    override fun run() {
        Log.d(TAG, "SocketNIODataService starting in background...")
        selector = SessionManager.INSTANCE.selector
        runTask()
    }

    /**
     * notify long running task to shutdown
     * @param shutdown to be shutdown or not
     */
    fun setShutdown(shutdown: Boolean) {
        this.shutdown = shutdown
        SessionManager.INSTANCE.selector!!.wakeup()
    }

    private fun runTask() {
        Log.d(TAG, "Selector is running...")

        while (!shutdown) {
            try {
                synchronized(syncSelector) {
                    selector!!.select()
                }
            } catch (e: IOException) {
                Log.e(TAG, "Error in Selector.select(): " + e.message)
                try {
                    Thread.sleep(100)
                } catch (ex: InterruptedException) {
                    Log.e(TAG, e.toString())
                }

                continue
            }

            if (shutdown) {
                break
            }

            synchronized(syncSelector2) {
                val iterator = selector!!.selectedKeys().iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    val selectableChannel = key.channel()
                    if (selectableChannel is SocketChannel) {
                        try {
                            processTCPSelectionKey(key)
                        } catch (e: IOException) {
                            key.cancel()
                        }

                    } else if (selectableChannel is DatagramChannel) {
                        processUDPSelectionKey(key)
                    }
                    iterator.remove()
                    if (shutdown) {
                        break
                    }
                }
            }
        }
    }

    private fun processUDPSelectionKey(key: SelectionKey) {
        if (!key.isValid) {
            Log.d(TAG, "Invalid SelectionKey for UDP")
            return
        }

        var channel = key.channel() as DatagramChannel
        val session = SessionManager.INSTANCE.getSessionByChannel(channel) ?: return

        if (!session.isConnected && key.isConnectable) {
            val ips = PacketUtil.intToIPAddress(session.destIp)
            val port = session.destPort
            val address = InetSocketAddress(ips, port)
            try {
                Log.d(TAG, "selector: connecting to remote UDP server: $ips:$port")
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

    @Throws(IOException::class)
    private fun processTCPSelectionKey(key: SelectionKey) {
        if (!key.isValid) {
            Log.d(TAG, "Invalid SelectionKey for TCP")
            return
        }
        val channel = key.channel() as SocketChannel
        val session = SessionManager.INSTANCE.getSessionByChannel(channel) ?: return

        if (!session.isConnected && key.isConnectable) {
            val ips = PacketUtil.intToIPAddress(session.destIp)
            val port = session.destPort
            val address = InetSocketAddress(ips, port)
            Log.d(TAG, "connecting to remote tcp server: $ips:$port")
            var connected = false
            if (!channel.isConnected && !channel.isConnectionPending) {
                try {
                    connected = channel.connect(address)
                } catch (e: ClosedChannelException) {
                    Log.e(TAG, e.toString())
                    session.isAbortingConnection = true
                } catch (e: UnresolvedAddressException) {
                    Log.e(TAG, e.toString())
                    session.isAbortingConnection = true
                } catch (e: UnsupportedAddressTypeException) {
                    Log.e(TAG, e.toString())
                    session.isAbortingConnection = true
                } catch (e: SecurityException) {
                    Log.e(TAG, e.toString())
                    session.isAbortingConnection = true
                } catch (e: IOException) {
                    Log.e(TAG, e.toString())
                    session.isAbortingConnection = true
                }
            }

            if (connected) {
                session.isConnected = connected
                Log.d(TAG, "connected immediately to remote tcp server: $ips:$port")
            } else {
                if (channel.isConnectionPending) {
                    connected = channel.finishConnect()
                    session.isConnected = connected
                    Log.d(TAG, "connected to remote tcp server: $ips:$port")
                }
            }
        }

        if (channel.isConnected) {
            processSelector(key, session)
        }
    }

    private fun processSelector(selectionKey: SelectionKey, session: Session) {
        val sessionKey = SessionManager.INSTANCE.createKey(
                session.destIp,
                session.destPort,
                session.sourceIp,
                session.sourcePort)

        // tcp has PSH flag when data is ready for sending, UDP does not have this
        if (selectionKey.isValid && selectionKey.isWritable
                && !session.isBusyWrite && session.hasDataToSend()
                && session.isDataForSendingReady) {
            session.isBusyWrite = true
            val worker = SocketDataWriterWorker(clientPacketWriter, sessionKey)
            workerPool.execute(worker)
        }

        if (selectionKey.isValid && selectionKey.isReadable
                && !session.isBusyRead) {
            session.isBusyRead = true
            val worker = SocketDataReaderWorker(clientPacketWriter, sessionKey)
            workerPool.execute(worker)
        }
    }
}
