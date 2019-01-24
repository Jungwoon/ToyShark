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

package com.lipisoft.toyshark.session;

import android.util.Log;

import com.lipisoft.toyshark.network.ip.IPv4Header;
import com.lipisoft.toyshark.transport.tcp.TCPHeader;
import com.lipisoft.toyshark.transport.udp.UDPHeader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.spi.AbstractSelectableChannel;

/**
 * store information about a socket connection from a VPN client.
 * Each session is used by background worker to server request from client.
 *
 * @author Borey Sao
 * Date: May 19, 2014
 */
public class Session {
    private static final String TAG = "Session";

    private AbstractSelectableChannel channel;

    private int destIp;
    private int destPort;
    private int sourceIp;
    private int sourcePort;

    // sequence received from client
    private long recSequence = 0;

    // track ack we sent to client and waiting for ack back from client
    private long sendUnAck = 0;

    // the next ack to send to client
    private long sendNext = 0;
    private int sendWindow = 0; //window = windowsize x windowscale
    private int sendWindowScale = 0;

    // sent by client during SYN inside tcp options
    private int maxSegmentSize = 0;

    // indicate that 3-way handshake has been completed or not
    private boolean isConnected = false;

    // receiving buffer for storing data from remote host
    private ByteArrayOutputStream receivingStream = new ByteArrayOutputStream();

    // sending buffer for storing data from vpn client to be send to destination host
    private ByteArrayOutputStream sendingStream = new ByteArrayOutputStream();

    private boolean hasReceivedLastSegment = false;

    // last packet received from client
    private IPv4Header lastIpHeader;
    private TCPHeader lastTcpHeader;
    private UDPHeader lastUdpHeader;

    // true when connection is about to be close
    private boolean closingConnection = false;

    // indicate data from client is ready for sending to destination
    private boolean isDataForSendingReady = false;

    private int timestampSender = 0;
    private int timestampReplyTo = 0;

    // indicate that this session is currently being worked on by some SocketDataWorker already
    private volatile boolean isBusyRead = false;
    private volatile boolean isBusyWrite = false;

    // closing session and aborting connection, will be done by background task
    private volatile boolean abortingConnection = false;

    private SelectionKey selectionkey = null;

    public long connectionStartTime = 0;

    public Session(int sourceIp, int sourcePort, int destIp, int destPort) {
        this.sourceIp = sourceIp;
        this.sourcePort = sourcePort;
        this.destIp = destIp;
        this.destPort = destPort;
    }

    /**
     * determine if client's receiving window is full or not.
     *
     * @return boolean
     */
    public boolean isClientWindowFull() {
        // track how many byte of data has been sent since last ACK from client
        return false;
    }

    /**
     * append more data
     *
     * @param data Data
     */
    public synchronized void addReceivedData(byte[] data) {
        try {
            receivingStream.write(data);
        } catch (IOException e) {
            Log.e(TAG, e.toString());
        }
    }

    /**
     * get all data received in the buffer and empty it.
     *
     * @return byte[]
     */
    public synchronized byte[] getReceivedData(int maxSize) {
        byte[] data = receivingStream.toByteArray();
        receivingStream.reset();
        if (data.length > maxSize) {
            byte[] small = new byte[maxSize];
            System.arraycopy(data, 0, small, 0, maxSize);
            int len = data.length - maxSize;
            receivingStream.write(data, maxSize, len);
            data = small;
        }
        return data;
    }

    /**
     * buffer has more data for vpn client
     *
     * @return boolean
     */
    public boolean hasReceivedData() {
        return receivingStream.size() > 0;
    }

    /**
     * set data to be sent to destination server
     *
     * @param data Data to be sent
     * @return boolean Success or not
     */
    synchronized boolean setSendingData(byte[] data) {
        try {
            sendingStream.write(data);
        } catch (IOException e) {
            Log.e(TAG, e.toString());
            return false;
        }
        return true;
    }

    int getSendingDataSize() {
        return sendingStream.size();
    }

    /**
     * dequeue data for sending to server
     *
     * @return byte[]
     */
    public synchronized byte[] getSendingData() {
        byte[] data = sendingStream.toByteArray();
        sendingStream.reset();
        return data;
    }

    /**
     * buffer contains data for sending to destination server
     *
     * @return boolean
     */
    public boolean hasDataToSend() {
        return sendingStream.size() > 0;
    }

    public int getDestIp() {
        return destIp;
    }

    public int getDestPort() {
        return destPort;
    }

    long getSendUnAck() {
        return sendUnAck;
    }

    void setSendUnAck(long sendUnAck) {
        this.sendUnAck = sendUnAck;
    }

    public long getSendNext() {
        return sendNext;
    }

    public void setSendNext(long sendNext) {
        this.sendNext = sendNext;
    }

    int getSendWindow() {
        return sendWindow;
    }

    public int getMaxSegmentSize() {
        return maxSegmentSize;
    }

    void setMaxSegmentSize(int maxSegmentSize) {
        this.maxSegmentSize = maxSegmentSize;
    }

    public boolean isConnected() {
        return isConnected;
    }

    public void setConnected(boolean isConnected) {
        this.isConnected = isConnected;
    }

    public int getSourceIp() {
        return sourceIp;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    void setSendWindowSizeAndScale(int sendWindowSize, int sendWindowScale) {
        this.sendWindowScale = sendWindowScale;
        this.sendWindow = sendWindowSize * sendWindowScale;
    }

    int getSendWindowScale() {
        return sendWindowScale;
    }

    public long getRecSequence() {
        return recSequence;
    }

    void setRecSequence(long recSequence) {
        this.recSequence = recSequence;
    }

    public AbstractSelectableChannel getChannel() {
        return channel;
    }

    public void setChannel(AbstractSelectableChannel channel) {
        this.channel = channel;
    }

    public boolean hasReceivedLastSegment() {
        return hasReceivedLastSegment;
    }

    public void setHasReceivedLastSegment(boolean hasReceivedLastSegment) {
        this.hasReceivedLastSegment = hasReceivedLastSegment;
    }

    public synchronized IPv4Header getLastIpHeader() {
        return lastIpHeader;
    }

    synchronized void setLastIpHeader(IPv4Header lastIpHeader) {
        this.lastIpHeader = lastIpHeader;
    }

    public synchronized TCPHeader getLastTcpHeader() {
        return lastTcpHeader;
    }

    synchronized void setLastTcpHeader(TCPHeader lastTcpHeader) {
        this.lastTcpHeader = lastTcpHeader;
    }

    public synchronized UDPHeader getLastUdpHeader() {
        return lastUdpHeader;
    }

    synchronized void setLastUdpHeader(UDPHeader lastUdpHeader) {
        this.lastUdpHeader = lastUdpHeader;
    }

    boolean isClosingConnection() {
        return closingConnection;
    }

    void setClosingConnection(boolean closingConnection) {
        this.closingConnection = closingConnection;
    }

    public boolean isDataForSendingReady() {
        return isDataForSendingReady;
    }

    void setDataForSendingReady(boolean isDataForSendingReady) {
        this.isDataForSendingReady = isDataForSendingReady;
    }

    public int getTimestampSender() {
        return timestampSender;
    }

    void setTimestampSender(int timestampSender) {
        this.timestampSender = timestampSender;
    }

    public int getTimestampReplyTo() {
        return timestampReplyTo;
    }

    void setTimestampReplyTo(int timestampReplyTo) {
        this.timestampReplyTo = timestampReplyTo;
    }

    boolean isAckToFin() {
        // indicate that vpn client has sent FIN flag and it has been acked
        return false;
    }

    public boolean isBusyRead() {
        return isBusyRead;
    }

    public void setBusyread(boolean isbusyread) {
        this.isBusyRead = isbusyread;
    }

    public boolean isBusywrite() {
        return isBusyWrite;
    }

    public void setBusywrite(boolean isbusywrite) {
        this.isBusyWrite = isbusywrite;
    }

    public boolean isAbortingConnection() {
        return abortingConnection;
    }

    public void setAbortingConnection(boolean abortingConnection) {
        this.abortingConnection = abortingConnection;
    }

    public SelectionKey getSelectionKey() {
        return selectionkey;
    }

    void setSelectionKey(SelectionKey selectionkey) {
        this.selectionkey = selectionkey;
    }
}
