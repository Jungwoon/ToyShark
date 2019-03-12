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

package com.lipisoft.toyshark.packet

import java.io.FileOutputStream
import java.io.IOException

/**
 * write packet data back to VPN client stream. This class is thread safe.
 * @author Borey Sao
 * Date: May 22, 2014
 */
class ClientPacketWriterImpl(private val clientWriter: FileOutputStream) : ClientPacketWriter {

    @Synchronized
    @Throws(IOException::class)
    override fun write(data: ByteArray) {
        clientWriter.write(data)
    }

    @Synchronized
    @Throws(IOException::class)
    override fun write(data: ByteArray, offset: Int, count: Int) {
        clientWriter.write(data, offset, count)
    }
}
