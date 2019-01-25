package com.lipisoft.toyshark.transport.udp

import com.lipisoft.toyshark.Packet
import com.lipisoft.toyshark.PacketManager
import com.lipisoft.toyshark.network.ip.IPPacketFactory
import com.lipisoft.toyshark.network.ip.IPv4Header
import com.lipisoft.toyshark.transport.tcp.PacketHeaderException
import com.lipisoft.toyshark.util.PacketUtil

import java.nio.ByteBuffer

object UDPPacketFactory {
    private const val TAG = "UDPPacketFactory"

    @Throws(PacketHeaderException::class)
    fun createUDPHeader(stream: ByteBuffer): UDPHeader {
        if (stream.remaining() < 8) {
            throw PacketHeaderException("Minimum UDP header is 8 bytes.")
        }
        val srcPort = stream.short.toInt()
        val destPort = stream.short.toInt()
        val length = stream.short.toInt()
        val checksum = stream.short.toInt()

        return UDPHeader(srcPort, destPort, length, checksum)
    }

    /**
     * create packet data for responding to vpn client
     *
     * @param ip         IPv4Header sent from VPN client, will be used as the template for response
     * @param udp        UDPHeader sent from VPN client
     * @param packetData packet data to be sent to client
     * @return array of byte
     */
    fun createResponsePacket(ip: IPv4Header, udp: UDPHeader, packetData: ByteArray?): ByteArray {
        val buffer: ByteArray
        var udpLen = 8
        if (packetData != null) {
            udpLen += packetData.size
        }
        val srcPort = udp.destinationPort
        val destPort = udp.sourcePort
        val checksum: Short = 0

        val ipHeader = IPPacketFactory.copyIPv4Header(ip)

        val srcIp = ip.destinationIP
        val destIp = ip.sourceIP
        ipHeader.isMayFragment = false
        ipHeader.sourceIP = srcIp
        ipHeader.destinationIP = destIp
        ipHeader.identification = PacketUtil.getPacketId()

        // ip's length is the length of the entire packet => IP header length + UDP header length (8) + UDP body length
        val totalLength = ipHeader.ipHeaderLength + udpLen

        ipHeader.totalLength = totalLength
        buffer = ByteArray(totalLength)
        val ipData = IPPacketFactory.createIPv4HeaderData(ipHeader)
        // calculate checksum for IP header
        val ipChecksum = PacketUtil.calculateChecksum(ipData, 0, ipData.size)
        // write result of checksum back to buffer
        System.arraycopy(ipChecksum, 0, ipData, 10, 2)
        System.arraycopy(ipData, 0, buffer, 0, ipData.size)

        // copy UDP header to buffer
        var start = ipData.size
        val intContainer = ByteArray(4)
        PacketUtil.writeIntToBytes(srcPort, intContainer, 0)

        // extract the last two bytes of int value
        System.arraycopy(intContainer, 2, buffer, start, 2)
        start += 2

        PacketUtil.writeIntToBytes(destPort, intContainer, 0)
        System.arraycopy(intContainer, 2, buffer, start, 2)
        start += 2

        PacketUtil.writeIntToBytes(udpLen, intContainer, 0)
        System.arraycopy(intContainer, 2, buffer, start, 2)
        start += 2

        PacketUtil.writeIntToBytes(checksum.toInt(), intContainer, 0)
        System.arraycopy(intContainer, 2, buffer, start, 2)
        start += 2

        //now copy udp data
        if (packetData != null)
            System.arraycopy(packetData, 0, buffer, start, packetData.size)

        val udpHeader = UDPHeader(srcPort, destPort, udpLen, checksum.toInt())

        PacketManager.INSTANCE.add(Packet(ipHeader, udpHeader, buffer))
        PacketManager.INSTANCE.handler.obtainMessage(PacketManager.PACKET).sendToTarget()

        return buffer
    }

}
