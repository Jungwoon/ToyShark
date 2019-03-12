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

package com.lipisoft.toyshark.network.ip

import com.lipisoft.toyshark.util.PacketHeaderException

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.experimental.and
import kotlin.experimental.or

/**
 * class for creating packet data, header etc related to IP
 *
 * @author Borey Sao
 * Date: June 30, 2014
 */
object IPPacketFactory {
    /**
     * make new instance of IPv4Header
     *
     * @param iPv4Header instance of IPv4Header
     * @return IPv4Header
     */
    fun copyIPv4Header(iPv4Header: IPv4Header): IPv4Header {
        return IPv4Header(
                ipVersion = iPv4Header.ipVersion,
                headerLength = iPv4Header.headerLength,
                dscp = iPv4Header.dscp,
                ecn = iPv4Header.ecn,
                totalLength = iPv4Header.totalLength,
                identification = iPv4Header.identification,
                mayFragment = iPv4Header.isMayFragment,
                lastFragment = iPv4Header.lastFragment,
                fragmentOffset = iPv4Header.fragmentOffset,
                timeToLive = iPv4Header.timeToLive,
                protocol = iPv4Header.protocol,
                headerChecksum = iPv4Header.headerChecksum,
                sourceIP = iPv4Header.sourceIP,
                destinationIP = iPv4Header.destinationIP)
    }

    /**
     * create IPv4 Header array of byte from a given IPv4Header object
     *
     * @param header instance of IPv4Header
     * @return array of byte
     */
    fun createIPv4HeaderData(header: IPv4Header): ByteArray {
        val buffer = ByteArray(header.ipHeaderLength)

        buffer[0] = (header.headerLength and 0xF or 0x40)
        buffer[1] = (header.dscp.toInt() shl 2).toByte() and (header.ecn and 0xFF.toByte())
        buffer[2] = (header.totalLength shr 8).toByte()
        buffer[3] = header.totalLength.toByte()
        buffer[4] = (header.identification shr 8).toByte()
        buffer[5] = header.identification.toByte()

        // combine flags and partial fragment offset
        buffer[6] = ((header.fragmentOffset.toInt() shr 8) and 0x1F or header.flag.toInt()).toByte()
        buffer[7] = header.fragmentOffset.toByte()
        buffer[8] = header.timeToLive
        buffer[9] = header.protocol
        buffer[10] = (header.headerChecksum shr 8).toByte()
        buffer[11] = header.headerChecksum.toByte()

        val buf = ByteBuffer.allocate(8)

        buf.order(ByteOrder.BIG_ENDIAN)
        buf.putInt(0, header.sourceIP)
        buf.putInt(4, header.destinationIP)

        // source ip ip
        System.arraycopy(buf.array(), 0, buffer, 12, 4)

        // destination ip ip
        System.arraycopy(buf.array(), 4, buffer, 16, 4)

        return buffer
    }

    /**
     * create IPv4 Header from a given ByteBuffer stream
     *
     * @param stream array of byte
     * @return a new instance of IPv4Header
     */
    @Throws(PacketHeaderException::class)
    fun createIPv4Header(stream: ByteBuffer): IPv4Header {
        // avoid Index out of range
        if (stream.remaining() < 20)
            throw PacketHeaderException("Minimum IPv4 header is 20 bytes. There are less than 20 bytes from start position to the end of array.")

        val versionAndHeaderLength = stream.get()
        val ipVersion = (versionAndHeaderLength.toInt() shr 4).toByte()
        if (ipVersion.toInt() != 0x04) throw PacketHeaderException("Invalid IPv4 header. IP version should be 4.")

        val internetHeaderLength = (versionAndHeaderLength and 0x0F)
        if (stream.capacity() < internetHeaderLength * 4) throw PacketHeaderException("Not enough space in array for IP header")

        val typeOfService = stream.get()
        val dscp = (typeOfService.toInt() shr 2).toByte()
        val ecn = (typeOfService and 0x03)
        val totalLength = stream.short.toInt()
        val identification = stream.short.toInt()
        val flagsAndFragmentOffset = stream.short
        val mayFragment = (flagsAndFragmentOffset and 0x4000).toInt() != 0
        val lastFragment = (flagsAndFragmentOffset and 0x2000).toInt() != 0
        val fragmentOffset = (flagsAndFragmentOffset and 0x1FFF)
        val timeToLive = stream.get()
        val protocol = stream.get()
        val checksum = stream.short.toInt()
        val sourceIp = stream.int
        val desIp = stream.int

        if (internetHeaderLength > 5) {
            // drop the IP option
            for (i in 0 until internetHeaderLength - 5) {
                stream.int
            }
        }
        return IPv4Header(
                ipVersion = ipVersion,
                headerLength = internetHeaderLength,
                dscp = dscp,
                ecn = ecn,
                totalLength = totalLength,
                identification = identification,
                mayFragment = mayFragment,
                lastFragment = lastFragment,
                fragmentOffset = fragmentOffset,
                timeToLive = timeToLive,
                protocol = protocol,
                headerChecksum = checksum,
                sourceIP = sourceIp,
                destinationIP = desIp
        )
    }
}
