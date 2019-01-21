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
package com.lipisoft.toyshark.transport.tcp;

import android.support.annotation.Nullable;

import com.lipisoft.toyshark.transport.ITransportHeader;

/**
 * data structure for TCP Header
 *
 * @author Borey Sao
 * Date: May 8, 2014
 */
public class TCPHeader implements ITransportHeader {
    private int sourcePort;
    private int destinationPort;
    private long sequenceNumber; // 32 bits
    private int dataOffset;
    private int tcpFlags;
    private boolean isNS;
    private boolean isCWR = false;
    private boolean isECE = false;
    private boolean isSYN = false;
    private boolean isACK = false;
    private boolean isFIN = false;
    private boolean isRST = false;
    private boolean isPSH = false;
    private boolean isURG = false;
    private int windowSize;
    private int checksum;
    private int urgentPointer;
    @Nullable
    private byte[] options;
    private long ackNumber; // 32 bits

    // vars below need to be set via setters when copy
    private int maxSegmentSize = 0;
    private int windowScale = 0;
    private boolean isSelectiveAckPermitted = false;
    private int timeStampSender = 0;
    private int timeStampReplyTo = 0;

    TCPHeader(int sourcePort, int destinationPort, long sequenceNumber, long ackNumber,
              int dataOffset, boolean isns, int tcpFlags,
              int windowSize, int checksum, int urgentPointer) {
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.sequenceNumber = sequenceNumber;
        this.dataOffset = dataOffset;
        this.isNS = isns;
        this.tcpFlags = tcpFlags;
        this.windowSize = windowSize;
        this.checksum = checksum;
        this.urgentPointer = urgentPointer;
        this.ackNumber = ackNumber;
        setFlagBits();
    }

    private void setFlagBits() {
        isFIN = (tcpFlags & 0x01) > 0;
        isSYN = (tcpFlags & 0x02) > 0;
        isRST = (tcpFlags & 0x04) > 0;
        isPSH = (tcpFlags & 0x08) > 0;
        isACK = (tcpFlags & 0x10) > 0;
        isURG = (tcpFlags & 0x20) > 0;
        isECE = (tcpFlags & 0x40) > 0;
        isCWR = (tcpFlags & 0x80) > 0;
    }

    public boolean isNS() {
        return isNS;
    }

    void setIsNS(boolean isNS) {
        this.isNS = isNS;
    }

    public boolean isCWR() {
        return isCWR;
    }

    void setIsCWR(boolean isCWR) {
        this.isCWR = isCWR;
        if (isCWR) {
            this.tcpFlags |= 0x80;
        } else {
            this.tcpFlags &= 0x7F;
        }
    }

    public boolean isECE() {
        return isECE;
    }

    void setIsECE(boolean isECE) {
        this.isECE = isECE;
        if (isECE) {
            this.tcpFlags |= 0x40;
        } else {
            this.tcpFlags &= 0xBF;
        }
    }

    public boolean isSYN() {
        return isSYN;
    }

    void setIsSYN(boolean isSYN) {
        this.isSYN = isSYN;
        if (isSYN) {
            this.tcpFlags |= 0x02;
        } else {
            this.tcpFlags &= 0xFD;
        }
    }

    public boolean isACK() {
        return isACK;
    }

    void setIsACK(boolean isACK) {
        this.isACK = isACK;
        if (isACK) {
            this.tcpFlags |= 0x10;
        } else {
            this.tcpFlags &= 0xEF;
        }
    }

    public boolean isFIN() {
        return isFIN;
    }

    void setIsFIN(boolean isFIN) {
        this.isFIN = isFIN;
        if (isFIN) {
            this.tcpFlags |= 0x1;
        } else {
            this.tcpFlags &= 0xFE;
        }
    }

    public boolean isRST() {
        return isRST;
    }

    void setIsRST(boolean isRST) {
        this.isRST = isRST;
        if (isRST) {
            this.tcpFlags |= 0x04;
        } else {
            this.tcpFlags &= 0xFB;
        }
    }

    public boolean isPSH() {
        return isPSH;
    }

    void setIsPSH(boolean isPSH) {
        this.isPSH = isPSH;
        if (isPSH) {
            this.tcpFlags |= 0x08;
        } else {
            this.tcpFlags &= 0xF7;
        }
    }

    public boolean isURG() {
        return isURG;
    }

    void setIsURG(boolean isURG) {
        this.isURG = isURG;
        if (isURG) {
            this.tcpFlags |= 0x20;
        } else {
            this.tcpFlags &= 0xDF;
        }
    }

    public int getSourcePort() {
        return sourcePort;
    }

    void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    void setDestinationPort(int destinationPort) {
        this.destinationPort = destinationPort;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    void setSequenceNumber(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public int getDataOffset() {
        return dataOffset;
    }

    public void setDataOffset(int dataOffset) {
        this.dataOffset = dataOffset;
    }

    int getTcpFlags() {
        return tcpFlags;
    }

    public void setTcpFlags(int tcpFlags) {
        this.tcpFlags = tcpFlags;
    }

    public int getWindowSize() {
        return windowSize;
    }

    void setWindowSize(int windowSize) {
        this.windowSize = windowSize;
    }

    public int getChecksum() {
        return checksum;
    }

    public void setChecksum(int checksum) {
        this.checksum = checksum;
    }

    public int getUrgentPointer() {
        return urgentPointer;
    }

    public void setUrgentPointer(int urgentPointer) {
        this.urgentPointer = urgentPointer;
    }

    @Nullable
    public byte[] getOptions() {
        return options;
    }

    void setOptions(@Nullable byte[] options) {
        this.options = options;
    }

    public long getAckNumber() {
        return ackNumber;
    }

    void setAckNumber(long ackNumber) {
        this.ackNumber = ackNumber;
    }

    /**
     * length of TCP Header including options length if available.
     *
     * @return int
     */
    public int getTCPHeaderLength() {
        return (dataOffset * 4);
    }

    public int getMaxSegmentSize() {
        return maxSegmentSize;
    }

    void setMaxSegmentSize(int maxSegmentSize) {
        this.maxSegmentSize = maxSegmentSize;
    }

    public int getWindowScale() {
        return windowScale;
    }

    void setWindowScale(int windowScale) {
        this.windowScale = windowScale;
    }

    boolean isSelectiveAckPermitted() {
        return isSelectiveAckPermitted;
    }

    void setSelectiveAckPermitted(boolean isSelectiveAckPermitted) {
        this.isSelectiveAckPermitted = isSelectiveAckPermitted;
    }

    public int getTimeStampSender() {
        return timeStampSender;
    }

    void setTimeStampSender(int timeStampSender) {
        this.timeStampSender = timeStampSender;
    }

    int getTimeStampReplyTo() {
        return timeStampReplyTo;
    }

    void setTimeStampReplyTo(int timeStampReplyTo) {
        this.timeStampReplyTo = timeStampReplyTo;
    }

}
