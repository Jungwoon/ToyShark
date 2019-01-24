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
package com.lipisoft.toyshark.transport.tcp

import com.lipisoft.toyshark.transport.ITransportHeader

/**
 * data structure for TCP Header
 *
 * @author Borey Sao
 * Date: May 8, 2014
 */
class TCPHeader (
        sourcePort: Int,
        destinationPort: Int,
        sequenceNumber: Long,
        ackNumber: Long,
        var dataOffset: Int,
        isNS: Boolean,
        tcpFlags: Int,
        windowSize: Int,
        var checksum: Int,
        var urgentPointer: Int) : ITransportHeader {

    override var sourcePort: Int = 0
    override var destinationPort: Int = 0

    var sequenceNumber: Long = 0

    var tcpFlags: Int = 0

    var isNS: Boolean = false
    var isCWR = false
    var isECE = false
    var isSYN = false
    var isACK = false
    var isFIN = false
    var isRST = false
    var isPSH = false
    var isURG = false

    var windowSize: Int = 0
    var options: ByteArray? = null
    var ackNumber: Long = 0

    // vars below need to be set via setters when copy
    var maxSegmentSize = 0
    var windowScale = 0
    var isSelectiveAckPermitted = false
    var timeStampSender = 0
    var timeStampReplyTo = 0

    /**
     * length of TCP Header including options length if available.
     *
     * @return int
     */
    val tcpHeaderLength: Int
        get() = dataOffset * 4

    init {
        this.sourcePort = sourcePort
        this.destinationPort = destinationPort
        this.sequenceNumber = sequenceNumber
        this.isNS = isNS
        this.tcpFlags = tcpFlags
        this.windowSize = windowSize
        this.ackNumber = ackNumber
        setFlagBits()
    }

    private fun setFlagBits() {
        isFIN = tcpFlags and 0x01 > 0
        isSYN = tcpFlags and 0x02 > 0
        isRST = tcpFlags and 0x04 > 0
        isPSH = tcpFlags and 0x08 > 0
        isACK = tcpFlags and 0x10 > 0
        isURG = tcpFlags and 0x20 > 0
        isECE = tcpFlags and 0x40 > 0
        isCWR = tcpFlags and 0x80 > 0
    }

    fun setIsCWR(isCWR: Boolean) {
        this.isCWR = isCWR
        if (isCWR) {
            this.tcpFlags = this.tcpFlags or 0x80
        } else {
            this.tcpFlags = this.tcpFlags and 0x7F
        }
    }

    fun setIsECE(isECE: Boolean) {
        this.isECE = isECE
        if (isECE) {
            this.tcpFlags = this.tcpFlags or 0x40
        } else {
            this.tcpFlags = this.tcpFlags and 0xBF
        }
    }

    fun setIsSYN(isSYN: Boolean) {
        this.isSYN = isSYN
        if (isSYN) {
            this.tcpFlags = this.tcpFlags or 0x02
        } else {
            this.tcpFlags = this.tcpFlags and 0xFD
        }
    }

    fun setIsACK(isACK: Boolean) {
        this.isACK = isACK
        if (isACK) {
            this.tcpFlags = this.tcpFlags or 0x10
        } else {
            this.tcpFlags = this.tcpFlags and 0xEF
        }
    }

    fun setIsFIN(isFIN: Boolean) {
        this.isFIN = isFIN
        if (isFIN) {
            this.tcpFlags = this.tcpFlags or 0x1
        } else {
            this.tcpFlags = this.tcpFlags and 0xFE
        }
    }

    fun setIsRST(isRST: Boolean) {
        this.isRST = isRST
        if (isRST) {
            this.tcpFlags = this.tcpFlags or 0x04
        } else {
            this.tcpFlags = this.tcpFlags and 0xFB
        }
    }

    fun setIsPSH(isPSH: Boolean) {
        this.isPSH = isPSH
        if (isPSH) {
            this.tcpFlags = this.tcpFlags or 0x08
        } else {
            this.tcpFlags = this.tcpFlags and 0xF7
        }
    }

    fun setIsURG(isURG: Boolean) {
        this.isURG = isURG
        if (isURG) {
            this.tcpFlags = this.tcpFlags or 0x20
        } else {
            this.tcpFlags = this.tcpFlags and 0xDF
        }
    }

}
