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
 * Singleton data structure for storing packet data in queue. Data is pushed into this queue from
 * VpnService as well as background worker that pull data from remote socket.
 *
 * @author Borey Sao
 * Date: May 12, 2014
 */
class SocketData {

    companion object {
        val instance = SocketData()
    }

    private var data: Queue<ByteArray>? = LinkedList()

    @Synchronized
    fun addData(packet: ByteArray) {
        data?.add(packet)
    }

    @Synchronized
    fun getData(): ByteArray? {
        return data?.poll()
    }
}
