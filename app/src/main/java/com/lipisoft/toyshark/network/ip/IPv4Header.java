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

package com.lipisoft.toyshark.network.ip;


/**
 * Data structure for IPv4 header as defined in RFC 791.
 *
 * @author Borey Sao
 * Date: May 8, 2014
 */
public class IPv4Header {
    private byte ipVersion;
    private byte headerLength;
    private byte dscp;
    private byte ecn;
    private int totalLength;
    private int identification;
    private byte flag = 0;
    private boolean mayFragment;
    private boolean lastFragment;
    private short fragmentOffset;
    private byte timeToLive;
    private byte protocol;
    private int headerChecksum;
    private int sourceIP;
    private int destinationIP;

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
     *                       the original unfragmented IP datagram.
     * @param timeToLive     8 bits field for preventing datagrams from persisting.
     * @param protocol       defines the protocol used in the data portion of the IP datagram
     * @param headerChecksum 16-bits field used for error-checking of the header
     * @param sourceIP       IPv4 address of sender.
     * @param destinationIP  IPv4 address of receiver.
     */
    IPv4Header(byte ipVersion,
               byte headerLength,
               byte dscp,
               byte ecn,
               int totalLength,
               int identification,
               boolean mayFragment,
               boolean lastFragment,
               short fragmentOffset,
               byte timeToLive,
               byte protocol,
               int headerChecksum,
               int sourceIP,
               int destinationIP) {

        this.ipVersion = ipVersion;
        this.headerLength = headerLength;
        this.dscp = dscp;
        this.ecn = ecn;
        this.totalLength = totalLength;
        this.identification = identification;
        this.mayFragment = mayFragment;

        if (mayFragment)
            this.flag |= 0x40;

        this.lastFragment = lastFragment;

        if (lastFragment)
            this.flag |= 0x20;

        this.fragmentOffset = fragmentOffset;
        this.timeToLive = timeToLive;
        this.protocol = protocol;
        this.headerChecksum = headerChecksum;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
    }

    public byte getIpVersion() {
        return ipVersion;
    }

    byte getHeaderLength() {
        return headerLength;
    }

    byte getDscp() {
        return dscp;
    }

    byte getEcn() {
        return ecn;
    }

    public int getTotalLength() {
        return totalLength;
    }

    public int getIPHeaderLength() {
        return (headerLength * 4);
    }

    public int getIdentification() {
        return identification;
    }

    public byte getFlag() {
        return flag;
    }

    public boolean isMayFragment() {
        return mayFragment;
    }

    public boolean isLastFragment() {
        return lastFragment;
    }

    public short getFragmentOffset() {
        return fragmentOffset;
    }

    public byte getTimeToLive() {
        return timeToLive;
    }

    public byte getProtocol() {
        return protocol;
    }

    public int getHeaderChecksum() {
        return headerChecksum;
    }

    public int getSourceIP() {
        return sourceIP;
    }

    public int getDestinationIP() {
        return destinationIP;
    }

    public void setTotalLength(int totalLength) {
        this.totalLength = totalLength;
    }

    public void setIdentification(int identification) {
        this.identification = identification;
    }

    public void setMayFragment(boolean mayFragment) {
        this.mayFragment = mayFragment;
        if (mayFragment) {
            this.flag |= 0x40;
        } else {
            this.flag &= 0xBF;
        }
    }

    public void setSourceIP(int sourceIP) {
        this.sourceIP = sourceIP;
    }

    public void setDestinationIP(int destinationIP) {
        this.destinationIP = destinationIP;
    }
}
