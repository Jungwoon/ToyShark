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

import kotlin.experimental.and
import kotlin.experimental.or


/**
 * Data structure for IPv4 header as defined in RFC 791.
 *
 * @author Borey Sao
 * Date: May 8, 2014
 */

/**
 * create a new IPv4 Header
 *
 * @param ipVersion      the first header field in an IP packet. It is four-bit. For IPv4, this has a value of 4.
 * @param headerLength   the second field (four bits) is the IP header length (from 20 to 60 bytes)
 * @param dscp           type of service
 * @param ecn            Explicit Congestion Notification
 * @param totalLength    total length of this packet including header and body in bytes (max 35535).
 * @param identification primarily used for uniquely identifying the group of fragments of a single IP datagram
 * @param mayFragment    bit number 1 of Flag. For DF (Don't Fragment)
 * @param lastFragment   bit number 2 of Flag. For MF (More Fragment)
 * @param fragmentOffset 13 bits long and specifies the offset of a particular fragment relative to the beginning of
 * the original unfragmented IP datagram.
 * @param timeToLive     8 bits field for preventing datagrams from persisting.
 * @param protocol       defines the protocol used in the data portion of the IP datagram
 * @param headerChecksum 16-bits field used for error-checking of the header
 * @param sourceIP       IPv4 address of sender.
 * @param destinationIP  IPv4 address of receiver.
 */
class IPv4Header(
        val ipVersion: Byte,
        val headerLength: Byte,
        val dscp: Byte,
        val ecn: Byte,
        var totalLength: Int,
        var identification: Int,
        private var mayFragment: Boolean,
        val isLastFragment: Boolean,
        val fragmentOffset: Short,
        val timeToLive: Byte,
        val protocol: Byte,
        val headerChecksum: Int,
        var sourceIP: Int,
        var destinationIP: Int) {

    var flag: Byte = 0

    init {
        if (mayFragment)
            this.flag = this.flag or 0x40

        if (isLastFragment)
            this.flag = this.flag or 0x20
    }

    val ipHeaderLength: Int
        get() = headerLength * 4

    var isMayFragment: Boolean
        get() = mayFragment
        set(mayFragment) {
            this.mayFragment = mayFragment
            if (mayFragment) {
                this.flag = this.flag or 0x40
            } else {
                this.flag = this.flag and 0xBF.toByte()
            }
        }

}
