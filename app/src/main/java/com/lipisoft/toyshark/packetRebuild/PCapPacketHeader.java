package com.lipisoft.toyshark.packetRebuild;

/**
 * Pkt header in the libcap file.
 * struct sf_pkthdr {
 * struct timeval  ts;
 * UINT            caplen;
 * UINT            len;
 * };
 * The caplen is the portion of the packet found in the cap (it's possible that only part of the packet will be recorded).
 * The len is the packet len as recorded.
 *
 * @author roni bar-yanai
 */

public class PCapPacketHeader {
    static final int HEADER_SIZE = 16;

    private long uInt32timeValSec = 0;

    private long uInt32timeValMsec = 0;

    private long uInt32CapLen = 0;

    private long uInt32PktLen = 0;

    private byte[] myOriginalCopy = null;


    /**
     * @return the header as little indian.
     */
    public byte[] getAsByteArray() {
        byte[] tmp = new byte[16];

        ByteUtils.setLittleIndianInBytesArray(tmp, 0, pcapRead32(uInt32timeValSec), 4);
        ByteUtils.setLittleIndianInBytesArray(tmp, 4, pcapRead32(uInt32timeValMsec), 4);
        ByteUtils.setLittleIndianInBytesArray(tmp, 8, pcapRead32(uInt32CapLen), 4);
        ByteUtils.setLittleIndianInBytesArray(tmp, 12, pcapRead32(uInt32PktLen), 4);

        return tmp;
    }

    /**
     * @return the header as read from the stream.
     */
    protected byte[] getTheHeaderByteArray() {
        return myOriginalCopy;
    }

    /**
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return "Time Sec: " + uInt32timeValSec + "\n" + "Time MSec : " + uInt32timeValMsec + "\n" + "Cap Len : " + uInt32CapLen + "\n" + "PKT Len : " + uInt32PktLen + "\n";
    }

    /**
     * The recorded packet portion.
     *
     * @param theCaplen32Uint
     */
    public void setuInt32CapLen(long theCaplen32Uint) {
        uInt32CapLen = theCaplen32Uint;
    }

    /**
     * The packet wire length.
     *
     * @param thePktlenUint32
     */
    public void setuInt32PktLen(long thePktlenUint32) {
        uInt32PktLen = thePktlenUint32;
    }

    /**
     * The time in microsec.
     *
     * @param theTimeValMsec32Uint
     */
    public void setuInt32timeValMsec(long theTimeValMsec32Uint) {
        uInt32timeValMsec = theTimeValMsec32Uint;
    }

    /**
     * the time in sec.
     *
     * @param theTimeValSec32Uint
     */
    public void setuInt32timeValSec(long theTimeValSec32Uint) {
        uInt32timeValSec = theTimeValSec32Uint;
    }

    private long pcapRead32(long num) {
        long tmp = num;
        tmp = ((tmp & 0x000000FF) << 24) + ((tmp & 0x0000FF00) << 8) + ((tmp & 0x00FF0000) >> 8) + ((tmp & 0xFF000000) >> 24);
        return tmp;
    }

    /**
     * @return
     */
    public long getuInt32timeValMsec() {
        return uInt32timeValMsec;
    }

    /**
     * @return
     */
    public long getuInt32timeValSec() {
        return uInt32timeValSec;
    }

    /**
     * @return
     */
    public long getTime() {
        return uInt32timeValSec * 1000000 + uInt32timeValMsec;
    }
}
