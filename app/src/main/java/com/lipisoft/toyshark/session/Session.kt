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
import com.lipisoft.toyshark.network.ip.IPv4Header
import com.lipisoft.toyshark.transport.tcp.TCPHeader
import com.lipisoft.toyshark.transport.udp.UDPHeader
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.lang.System.arraycopy
import java.nio.channels.SelectionKey
import java.nio.channels.spi.AbstractSelectableChannel

/**
 * store information about a socket connection from a VPN client.
 * Each session is used by background worker to server request from client.
 *
 * @author Borey Sao
 * Date: May 19, 2014
 */
class Session(
        val sourceIp: Int,
        val sourcePort: Int,
        val destIp: Int,
        val destPort: Int) {

    companion object {
        private const val TAG = "Session"
    }

    var channel: AbstractSelectableChannel? = null

    var recSequence = 0L

    var sendUnAck = 0L

    var isAck = false

    var sendNext = 0L

    var sendWindow = 0

    var sendWindowScale = 0

    var maxSegmentSize = 0

    var isConnected = false

    private val receivingStream = ByteArrayOutputStream()

    private val sendingStream = ByteArrayOutputStream()

    var hasReceivedLastSegment = false

    var lastIpHeader: IPv4Header? = null

    var lastTcpHeader: TCPHeader? = null

    var lastUdpHeader: UDPHeader? = null

    var isClosingConnection = false

    var isDataForSendingReady = false

    var timestampSender = 0

    var timestampReplyTo = 0

    @Volatile
    var isBusyRead = false

    @Volatile
    var isBusyWrite = false

    @Volatile
    var isAbortingConnection = false

    var selectionKey: SelectionKey? = null

    var connectionStartTime = 0L

    var isClientWindowFull: Boolean = false

    var isAckToFin: Boolean = false

    @Synchronized
    fun addReceivedData(data: ByteArray) {
        receivingStream.write(data)
    }

    @Synchronized
    fun getReceivedData(maxSize: Int): ByteArray {
        var data = receivingStream.toByteArray()
        receivingStream.reset()

        if (data.size > maxSize) {
            val small = ByteArray(maxSize)

            arraycopy(data, 0, small, 0, maxSize)

            val length = data.size - maxSize
            receivingStream.write(data, maxSize, length)

            data = small
        }
        return data
    }

    fun hasDataToSend() = sendingStream.size() > 0

    fun hasReceivedData() = receivingStream.size() > 0

    fun getSendingDataSize() = sendingStream.size()

    @Synchronized
    fun getSendingData(): ByteArray {
        val data = sendingStream.toByteArray()
        sendingStream.reset()
        return data
    }

    @Synchronized
    fun setSendingData(data: ByteArray): Boolean {
        try {
            sendingStream.write(data)
        } catch (e: IOException) {
            Log.e(TAG, e.toString())
            return false
        }

        return true
    }

    fun setSendWindowSizeAndScale(sendWindowSize: Int, sendWindowScale: Int) {
        this.sendWindowScale = sendWindowScale
        this.sendWindow = sendWindowSize * sendWindowScale
    }

}
