/*
 *  Copyright 2016 Lipi C.H. Lee
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
package com.lipisoft.toyshark

import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Message
import android.os.ParcelFileDescriptor
import android.util.Log
import android.widget.Toast
import com.lipisoft.toyshark.packet.ClientPacketWriterImpl

import com.lipisoft.toyshark.session.SessionHandler
import com.lipisoft.toyshark.socket.IProtectSocket
import com.lipisoft.toyshark.socket.SocketNIODataService
import com.lipisoft.toyshark.socket.SocketProtector
import com.lipisoft.toyshark.util.PacketHeaderException

import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket
import java.nio.ByteBuffer

class ToySharkVPNService : VpnService(), Handler.Callback, Runnable, IProtectSocket {

    private var mainThread: Thread? = null
    private var fileDescriptor: ParcelFileDescriptor? = null
    private var serviceValid: Boolean = false
    private var socketNIODataService: SocketNIODataService? = null
    private var dataServiceThread: Thread? = null
    private var packetQueueThread: Thread? = null

    companion object {
        private const val TAG = "ToySharkVPNService"
        private const val MAX_PACKET_LEN = 1500
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand")

        // Stop the previous session by interrupting the mainThread.
        if (mainThread != null) {
            mainThread!!.interrupt()
            var reps = 0
            while (mainThread!!.isAlive) {
                Log.i(TAG, "Waiting to exit " + ++reps)
                try {
                    Thread.sleep(1000)
                } catch (e: InterruptedException) {
                    e.printStackTrace()
                }
            }
        }

        // Start a new session by creating a new mainThread.
        mainThread = Thread(this, "CaptureThread")
        mainThread!!.start()
        return START_STICKY
    }


    /**
     * onDestroy is invoked when user disconnects the VPN
     */
    override fun onDestroy() {
        Log.i(TAG, "onDestroy()")
        serviceValid = false

        socketNIODataService?.setShutdown(true)
        dataServiceThread?.interrupt()
        packetQueueThread?.interrupt()
        fileDescriptor?.close()

        // Stop the previous session by interrupting the mainThread.
        if (mainThread != null) {
            mainThread?.interrupt()
            var reps = 0
            while (mainThread!!.isAlive) {
                Log.i(TAG, "Waiting to exit " + ++reps)

                try {
                    Thread.sleep(1000)
                } catch (e: InterruptedException) {
                    e.printStackTrace()
                }

                if (reps > 5) {
                    break
                }
            }
            mainThread = null
        }
    }

    override fun run() {
        Log.i(TAG, "running vpnService")
        val protector = SocketProtector.getInstance()
        protector!!.setProtector(this)

        try {
            if (startVpnService()) {
                startCapture()
                Log.i(TAG, "Capture completed")
            } else {
                Log.e(TAG, "Failed to start VPN Service!")
            }
        } catch (e: IOException) {
            Log.e(TAG, e.message)
        }

        Log.i(TAG, "Closing Capture files")
    }

    /**
     * setup VPN interface.
     *
     * @return boolean
     */
    private fun startVpnService(): Boolean {
        if (fileDescriptor != null) {
            Log.i(TAG, "Using the previous interface")
            return false
        }

        Log.i(TAG, "startVpnService => create builder")

        // Configure a builder while parsing the parameters.
        val builder = Builder()
                .addAddress("10.120.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .setSession("ToyShark")

        fileDescriptor = builder.establish()

        return if (fileDescriptor != null) {
            Log.i(TAG, "VPN Established:interface = " + fileDescriptor!!.fileDescriptor.toString())
            true
        } else {
            Log.d(TAG, "fileDescriptor is null")
            false
        }
    }

    /**
     * start background mainThread to handle client's socket, handle incoming and outgoing packet from VPN interface
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    fun startCapture() {
        Log.i(TAG, "startCapture() :capture starting")

        val clientReadStream = FileInputStream(fileDescriptor!!.fileDescriptor) // input stream
        val clientWriteStream = FileOutputStream(fileDescriptor!!.fileDescriptor) // output stream

        // Allocate the buffer for a single packet.
        val packetBuffer = ByteBuffer.allocate(MAX_PACKET_LEN)
        val clientPacketWriter = ClientPacketWriterImpl(clientWriteStream)

        SessionHandler.setWriter(clientPacketWriter)

        // 백그라운드에서 non-blocking 소켓에 쓰는 부분
        socketNIODataService = SocketNIODataService(clientPacketWriter)
        dataServiceThread = Thread(socketNIODataService)
        dataServiceThread!!.start()

        var packetData: ByteArray
        var packetDataLength: Int

        serviceValid = true

        // VPN Client 로부터 패킷을 읽는 부분
        while (serviceValid) {
            packetData = packetBuffer.array()
            packetDataLength = clientReadStream.read(packetData)

            if (hasPacketData(packetDataLength)) {
                try {
                    packetBuffer.limit(packetDataLength) // 포인터의 끝
                    SessionHandler.handlePacket(packetBuffer)
                } catch (e: PacketHeaderException) {
                    Log.e(TAG, e.message)
                }

                packetBuffer.clear()

            } else {
                try {
                    Thread.sleep(100)
                } catch (e: InterruptedException) {
                    Log.d(TAG, "Failed to sleep: " + e.message)
                }
            }
        }
        Log.i(TAG, "capture finished: serviceValid = $serviceValid")
    }

    private fun hasPacketData(length: Int) = length > 0

    override fun handleMessage(message: Message?): Boolean {
        if (message != null) {
            Log.d(TAG, "handleMessage:" + getString(message.what))
            Toast.makeText(this.applicationContext, message.what, Toast.LENGTH_SHORT).show()
        }
        return true
    }

    override fun protectSocket(socket: DatagramSocket) {
        this.protect(socket)
    }

    override fun protectSocket(socket: Socket) {
        this.protect(socket)
    }

    override fun protectSocket(socket: Int) {
        this.protect(socket)
    }

}
