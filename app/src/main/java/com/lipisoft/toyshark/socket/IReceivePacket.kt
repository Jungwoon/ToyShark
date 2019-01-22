package com.lipisoft.toyshark.socket

interface IReceivePacket {
    fun receive(packet: ByteArray)
}
