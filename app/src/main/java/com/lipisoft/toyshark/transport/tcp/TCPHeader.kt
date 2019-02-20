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

    var sequenceNumber: Long = 0 // 전송되는 데이터의 Byte 순서 번호, 랜덤한 숫자가 들어감

    var tcpFlags: Int = 0

    var isNS: Boolean = false // ECN-nonce 은폐 보호
    var isCWR = false // 혼잡 윈도 축소 플래그는 송식측 호스트에 의해 성정되는것
    var isECE = false // SYN=1 : TCP 가 명시적 혼잡 통지가 가능한 상태 / SYN=0 : IP 헤더 셋에 혼잡 경험 플래그가 설정된 패킷이 정상 수신
    var isSYN = false // 연결 요청 : TCP 에서 세션 성립시 가장 먼저 보내는 패킷, 임의의 시퀀스 번호를 보내어 설정
    var isACK = false // 응답 : 상대방으로부터 패킷을 받았다는 패킷 (보통 +1), ACK 응답으로 성공 실패를 판단
    var isFIN = false // 종료 : 세션 연결을 종료시킬때 사용, 더 이상 전송할 데이터가 없음
    var isRST = false // 강제 종료 : Reset 과정이며, 양방향에서 동시에 일어나는 중단 작업
    var isPSH = false // 밀어넣기 플래그 : 상호작용이 중요한 프로토콜인 경우 빠른 응답을 위해 7Layer에 전송
    var isURG = false // 긴급 : 헤더를 참조하여 어디~어디까지 우선 보내달라는 플래그

    var windowSize: Int = 0 // 이만큼 보낼 수 있다 (송신 윈도우), 이만큼 바등ㄹ 수 있다 (수신 윈도우) 최대:65535, 혼잡제어용
    var windowScale = 0

    var ackNumber: Long = 0 // 수신측에서 앞으로 받고자 하는 byte 순서 번호, 마지막으로 받은 데이터에 seq+1을 함
    var options: ByteArray? = null // 연결이 구성되는 동안 협상할 최대 세그먼트 옵션

    // vars below need to be set via setters when copy
    var maxSegmentSize = 0
    var isSelectiveAckPermitted = false
    var timeStampSender = 0
    var timeStampReplyTo = 0

    /**
     * length of TCP Header including options length if available.
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
