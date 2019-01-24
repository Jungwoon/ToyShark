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

import java.util.ArrayList

import android.util.Log

/**
 * Publish packet socketData to subscriber who implements interface IReceivePacket
 *
 * @author Borey Sao
 * Date: June 15, 2014
 */
class SocketDataPublisher : Runnable {
    private val TAG = "SocketDataPublisher"

    private val subscribers: MutableList<IReceivePacket>
    private val socketData: SocketData = SocketData.instance
    @Volatile
    var isShuttingDown = false

    init {
        subscribers = ArrayList()
    }

    /**
     * register a subscriber who wants to receive packet socketData
     *
     * @param subscriber a subscriber who wants to receive packet socketData
     */
    fun subscribe(subscriber: IReceivePacket) {
        if (!subscribers.contains(subscriber)) {
            subscribers.add(subscriber)
        }
    }

    override fun run() {
        Log.d(TAG, "BackgroundWriter starting...")

        while (!isShuttingDown) {
            val packetData = socketData.getData()

            if (packetData != null) {
                for (subscriber in subscribers) {
                    subscriber.receive(packetData)
                }
            }

        }
        Log.d(TAG, "BackgroundWriter ended")
    }
}
