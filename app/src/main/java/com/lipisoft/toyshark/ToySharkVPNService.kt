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

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Message
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import android.widget.Toast

import com.lipisoft.toyshark.packetRebuild.PCapFileWriter
import com.lipisoft.toyshark.session.SessionHandler
import com.lipisoft.toyshark.socket.IProtectSocket
import com.lipisoft.toyshark.socket.IReceivePacket
import com.lipisoft.toyshark.socket.SocketDataPublisher
import com.lipisoft.toyshark.socket.SocketNIODataService
import com.lipisoft.toyshark.socket.SocketProtector
import com.lipisoft.toyshark.transport.tcp.PacketHeaderException

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.Locale

class ToySharkVPNService : VpnService(), Handler.Callback, Runnable, IProtectSocket, IReceivePacket {

    private var mHandler: Handler? = null
    private var mThread: Thread? = null
    private var fileDescriptor: ParcelFileDescriptor? = null
    private var serviceValid: Boolean = false
    private var dataService: SocketNIODataService? = null
    private var dataServiceThread: Thread? = null
    private var socketDataPublisher: SocketDataPublisher? = null
    private var packetQueueThread: Thread? = null
    private var traceDir: File? = null
    private var pCapFileWriter: PCapFileWriter? = null
    private var timeStream: FileOutputStream? = null

    companion object {
        private const val TAG = "ToySharkVPNService"
        private const val MAX_PACKET_LEN = 1500
    }

    /**
     * receive message to trigger termination of collection
     */
    private var serviceCloseCmdReceiver: BroadcastReceiver? = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            Log.d(TAG, "received service close cmd intent at " + System.currentTimeMillis())
            unregisterAnalyzerCloseCmdReceiver()
            serviceValid = false
            stopSelf()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand")

        if (intent != null) {
            loadExtras(intent)
        } else {
            return START_STICKY
        }

        try {
            initTraceFiles()
        } catch (e: IOException) {
            e.printStackTrace()
            stopSelf()
            return START_STICKY
        }

        // The handler is only used to show messages.
        if (mHandler == null) {
            mHandler = Handler(this)
        }

        // Stop the previous session by interrupting the thread.
        if (mThread != null) {
            mThread!!.interrupt()
            var reps = 0
            while (mThread!!.isAlive) {
                Log.i(TAG, "Waiting to exit " + ++reps)
                try {
                    Thread.sleep(1000)
                } catch (e: InterruptedException) {
                    e.printStackTrace()
                }

            }
        }

        // Start a new session by creating a new thread.
        mThread = Thread(this, "CaptureThread")
        mThread!!.start()
        return START_STICKY
    }

    private fun loadExtras(intent: Intent) {
        val traceDirStr = intent.getStringExtra("TRACE_DIR")
        traceDir = File(traceDirStr)
    }

    private fun unregisterAnalyzerCloseCmdReceiver() {
        Log.d(TAG, "inside unregisterAnalyzerCloseCmdReceiver()")
        try {
            if (serviceCloseCmdReceiver != null) {
                unregisterReceiver(serviceCloseCmdReceiver)
                serviceCloseCmdReceiver = null
                Log.d(TAG, "successfully unregistered serviceCloseCmdReceiver")
            }
        } catch (e: Exception) {
            Log.d(TAG, "Ignoring exception in serviceCloseCmdReceiver", e)
        }

    }

    /**
     * called back from background thread when new packet arrived
     */
    override fun receive(packet: ByteArray) {
        if (pCapFileWriter != null) {
            try {
                pCapFileWriter!!.addPacket(packet, 0, packet.size, System.currentTimeMillis() * 1000000)
            } catch (e: IOException) {
                Log.e(TAG, "pCapFileWriter.addPacket IOException :" + e.message)
                e.printStackTrace()
            }

        } else {
            Log.e(TAG, "overrun from capture: length:" + packet.size)
        }

    }

    /**
     * Close the packet trace file
     */
    private fun closePCapTrace() {
        Log.i(TAG, "closePCapTrace()")
        if (pCapFileWriter != null) {
            pCapFileWriter!!.close()
            pCapFileWriter = null
            Log.i(TAG, "closePCapTrace() closed")
        }
    }

    /**
     * onDestroy is invoked when user disconnects the VPN
     */
    override fun onDestroy() {
        Log.i(TAG, "onDestroy()")
        serviceValid = false

        unregisterAnalyzerCloseCmdReceiver()

        if (dataService != null)
            dataService!!.setShutdown(true)

        if (socketDataPublisher != null)
            socketDataPublisher!!.setShuttingDown(true)

        //	closeTraceFiles();

        if (dataServiceThread != null) {
            dataServiceThread!!.interrupt()
        }
        if (packetQueueThread != null) {
            packetQueueThread!!.interrupt()
        }

        try {
            if (fileDescriptor != null) {
                Log.i(TAG, "fileDescriptor.close()")
                fileDescriptor!!.close()
            }
        } catch (e: IOException) {
            Log.d(TAG, "fileDescriptor.close():" + e.message)
            e.printStackTrace()
        }

        // Stop the previous session by interrupting the thread.
        if (mThread != null) {
            mThread!!.interrupt()
            var reps = 0
            while (mThread!!.isAlive) {
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
            mThread = null
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
        closeTraceFiles()
    }

    /**
     * create, open, initialize trace files
     */
    @Throws(IOException::class)
    private fun initTraceFiles() {
        Log.i(TAG, "initTraceFiles()")
        initPcapFile()
        instantiateTimeFile()
    }

    /**
     * close the trace files
     */
    private fun closeTraceFiles() {
        Log.i(TAG, "closeTraceFiles()")
        closePCapTrace()
        closeTimeFile()
    }

    /**
     * Create and leave open, the pcap file
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun initPcapFile() {
        if (!traceDir!!.exists())
            if (!traceDir!!.mkdirs())
                Log.e(TAG, "CANNOT make " + traceDir!!.toString())

        // gen & open pcap file
        val sFileName = "ToyShark.pcapng"
        val pcapFile = File(traceDir, sFileName)
        pCapFileWriter = PCapFileWriter(pcapFile)
    }

    /**
     * Create and leave open, the time file
     * time file format
     * line 1: header
     * line 2: pcap start time
     * line 3: eventtime or uptime (doesn't appear to be used)
     * line 4: pcap stop time
     * line 5: time zone offset
     */
    @Throws(IOException::class)
    private fun instantiateTimeFile() {

        if (!traceDir!!.exists())
            if (!traceDir!!.mkdirs())
                Log.e(TAG, "CANNOT make " + traceDir!!.toString())

        // gen & open pcap file
        val sFileName = "time"
        val timeFile = File(traceDir, sFileName)
        timeStream = FileOutputStream(timeFile)

        val str = String.format(Locale.ENGLISH, "%s\n%.3f\n%d\n", "Synchronized timestamps", System.currentTimeMillis().toDouble() / 1000.0, SystemClock.uptimeMillis()
        )

        try {
            timeStream!!.write(str.toByteArray())
        } catch (e: IOException) {
            e.printStackTrace()
        }

    }

    /**
     * update and close the time file
     */
    private fun closeTimeFile() {
        Log.i(TAG, "closeTimeFile()")
        if (timeStream != null) {
            val str = String.format(Locale.ENGLISH, "%.3f\n", System.currentTimeMillis().toDouble() / 1000.0)
            try {
                timeStream!!.write(str.toByteArray())
                timeStream!!.flush()
                timeStream!!.close()
                Log.i(TAG, "...closed")
            } catch (e: IOException) {
                Log.e(TAG, "IOException:" + e.message)
            }

        }
    }

    /**
     * setup VPN interface.
     *
     * @return boolean
     */
    private fun startVpnService(): Boolean {
        // If the old interface has exactly the same parameters, use it!
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

        if (fileDescriptor != null) {
            Log.i(TAG, "VPN Established:interface = " + fileDescriptor!!.fileDescriptor.toString())
            return true
        } else {
            Log.d(TAG, "fileDescriptor is null")
            return false
        }
    }

    /**
     * start background thread to handle client's socket, handle incoming and outgoing packet from VPN interface
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    internal fun startCapture() {

        Log.i(TAG, "startCapture() :capture starting")

        // Packets to be sent are queued in this input stream.
        val clientReader = FileInputStream(fileDescriptor!!.fileDescriptor)

        // Packets received need to be written to this output stream.
        val clientWriter = FileOutputStream(fileDescriptor!!.fileDescriptor)

        // Allocate the buffer for a single packet.
        val packet = ByteBuffer.allocate(MAX_PACKET_LEN)
        val clientPacketWriter = ClientPacketWriterImpl(clientWriter)

        val handler = SessionHandler.getInstance()
        handler.setWriter(clientPacketWriter)

        // background task for non-blocking socket
        dataService = SocketNIODataService(clientPacketWriter)
        dataServiceThread = Thread(dataService)
        dataServiceThread!!.start()

        // background task for writing packet data to pcap file
        socketDataPublisher = SocketDataPublisher()
        socketDataPublisher!!.subscribe(this)
        packetQueueThread = Thread(socketDataPublisher)
        packetQueueThread!!.start()

        var data: ByteArray
        var length: Int
        serviceValid = true
        while (serviceValid) {
            // read packet from vpn client
            data = packet.array()
            length = clientReader.read(data)
            if (length > 0) {
                try {
                    packet.limit(length)
                    handler.handlePacket(packet)
                } catch (e: PacketHeaderException) {
                    Log.e(TAG, e.message)
                }

                packet.clear()
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
