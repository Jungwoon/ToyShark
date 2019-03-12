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

import java.net.DatagramSocket
import java.net.Socket


/**
 * Singleton class that is created in child class of VpnService which implement IProtectSocket,
 * then this class is used everywhere else that need to protect socket from going through VPN interface.
 *
 * @author Borey Sao
 * Date: June 1, 2014
 */
class SocketProtector {

    companion object {
        private val synObject = Any()

        @Volatile
        private var instance: SocketProtector? = null

        fun getInstance(): SocketProtector? {
            if (instance == null) {
                synchronized(synObject) {
                    if (instance == null) {
                        instance = SocketProtector()
                    }
                }
            }
            return instance
        }
    }

    private var protector: IProtectSocket? = null

    /**
     * set class that implement IProtectSocket if only if it was never set before.
     */
    fun setProtector(protector: IProtectSocket) {
        if (this.protector == null)
            this.protector = protector
    }

    fun protect(socket: Socket) {
        protector!!.protectSocket(socket)
    }

    fun protect(socket: DatagramSocket) {
        protector!!.protectSocket(socket)
    }
}
