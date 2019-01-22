package com.lipisoft.toyshark.socket

import java.net.DatagramSocket
import java.net.Socket

interface IProtectSocket {
    fun protectSocket(socket: Socket)

    fun protectSocket(socket: Int)

    fun protectSocket(socket: DatagramSocket)
}
