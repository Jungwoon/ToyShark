package com.lipisoft.toyshark.packetRebuild

import com.lipisoft.toyshark.util.ByteUtils

internal object StubbedEthernetHeader {

    // set destination mac to be all 0s
    // set src mac, random to be 1
    // set eth type: 0x0800 = 2048
    val ethernetHeader: ByteArray
        get() {
            val ethHeader = ByteArray(14)
            ByteUtils.setBigIndianInBytesArray(ethHeader, 0, 0, 6)
            ByteUtils.setBigIndianInBytesArray(ethHeader, 6, 1, 6)
            ByteUtils.setBigIndianInBytesArray(ethHeader, 12, 2048, 2)

            return ethHeader
        }
}
