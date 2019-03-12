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
package com.lipisoft.toyshark.socket

import java.util.LinkedList
import java.util.Queue

/**
 * Singleton packet structure for storing packet packet in queue. Data is pushed into this queue from
 * VpnService as well as background worker that pull packet from remote socket.
 *
 * @author Borey Sao
 * Date: May 12, 2014
 */
class RawPacketQueue {

    companion object {
        val instance = RawPacketQueue()
    }

    private var packet: Queue<ByteArray>? = LinkedList()

    @Synchronized
    fun addPacket(packet: ByteArray) {
        this.packet?.add(packet)
    }

    @Synchronized
    fun getPacket(): ByteArray? {
        return packet?.poll()
    }
}
