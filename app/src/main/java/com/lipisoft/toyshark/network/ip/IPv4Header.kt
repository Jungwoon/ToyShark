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
        val ipVersion: Byte, // 보통 IPv4이기 때문에 4가 들어감
        val headerLength: Byte,
        val dscp: Byte, // 어떤 데이터를 먼저 처리할지 우선순위 처리
        val ecn: Byte, // 높으면 중요하지 않은 데이터, 낮으면 중요한 데이터
        var totalLength: Int, // L3 헤더까지 합쳐서 데이터 전체 사이즈
        var identification: Int, // 쪼개서 전송시에 조립하기 위한 아이디
        private var mayFragment: Boolean, // 쪼갰는지 아닌지
        val lastFragment: Boolean, // 마지막 조각인지 판단
        val fragmentOffset: Short, // 쪼개진 패킷의 순서
        val timeToLive: Byte, // Loop 방지를 위해서 라우팅할때마다 1씩 줄어들어 0이 되면 drop
        val protocol: Byte, // IP Header 다음에 어떤 프로토콜이 오는지 정의 ex) 6(TCP)
        val headerChecksum: Int, // Header가 정상인지 아닌지 판단
        var sourceIP: Int,
        var destinationIP: Int) {

    var flag: Byte = 0

    init {
        if (mayFragment)
            this.flag = this.flag or 0x40

        if (lastFragment)
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
