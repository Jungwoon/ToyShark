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

package com.lipisoft.toyshark

import com.lipisoft.toyshark.network.ip.IPv4Header
import com.lipisoft.toyshark.transport.ITransportHeader

/**
 * Data structure that encapsulate both IPv4Header and TCPHeader
 * @author Borey Sao
 * Date: May 27, 2014
 */
class Packet(val ipHeader: IPv4Header,
             val transportHeader: ITransportHeader,
             val buffer: ByteArray) {

    val protocol: Byte
        get() = ipHeader.protocol

    val sourcePort: Int
        get() = transportHeader.sourcePort

    val destinationPort: Int
        get() = transportHeader.destinationPort

}
