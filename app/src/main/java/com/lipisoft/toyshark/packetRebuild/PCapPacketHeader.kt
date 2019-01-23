package com.lipisoft.toyshark.packetRebuild

import com.lipisoft.toyshark.util.ByteUtils

/**
 * Pkt header in the libcap file.
 * struct sf_pkthdr {
 * struct timeval  ts;
 * UINT            caplen;
 * UINT            len;
 * };
 * The caplen is the portion of the packet found in the cap (it's possible that only part of the packet will be recorded).
 * The len is the packet len as recorded.
 *
 * @author roni bar-yanai
 */

class PCapPacketHeader {
    private var timeSec: Long = 0
    private var timeMilliSec: Long = 0
    private var capLength: Long = 0
    private var packetLength: Long = 0

    companion object {
        const val HEADER_SIZE = 16
    }

    /**
     * @return the header as little indian.
     */
    val asByteArray: ByteArray
        get() {
            val tmp = ByteArray(16)

            ByteUtils.setLittleIndianInBytesArray(tmp, 0, pCapRead(timeSec), 4)
            ByteUtils.setLittleIndianInBytesArray(tmp, 4, pCapRead(timeMilliSec), 4)
            ByteUtils.setLittleIndianInBytesArray(tmp, 8, pCapRead(capLength), 4)
            ByteUtils.setLittleIndianInBytesArray(tmp, 12, pCapRead(packetLength), 4)

            return tmp
        }

    val time: Long
        get() = timeSec * 1000000 + timeMilliSec

    override fun toString(): String {
        return "Time Sec: $timeSec\nTime MSec : $timeMilliSec\nCap Len : $capLength\nPKT Len : $packetLength\n"
    }

    fun setTimeSec(timeSec: Long) {
        this.timeSec = timeSec
    }

    fun setTimeMilliSec(timeMilliSec: Long) {
        this.timeMilliSec = timeMilliSec
    }

    fun setCapLength(capLength: Long) {
        this.capLength = capLength
    }

    fun setPacketLength(packetLength: Long) {
        this.packetLength = packetLength
    }

    private fun pCapRead(num: Long): Long {
        var tmp = num
        tmp = (tmp and 0x000000FF shl 24) + (tmp and 0x0000FF00 shl 8) + (tmp and 0x00FF0000 shr 8) + (tmp and -0x1000000 shr 24)
        return tmp
    }
}
