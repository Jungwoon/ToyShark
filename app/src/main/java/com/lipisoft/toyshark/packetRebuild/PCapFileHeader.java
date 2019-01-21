package com.lipisoft.toyshark.packetRebuild;

import java.io.IOException;
import java.io.InputStream;

/**
 * Class for holding libcap file header data structure.<br>
 * Each libcap start with this header.<br>
 *
 * @author roni bar yanai
 */
public class PCapFileHeader {
    static final int HEADER_SIZE = 24;

    private long uInt32MagicNum;

    private int uShort16VersionMajor;

    private int uShort16VersionMinor;

    private long uInt32ThisTimeZone;

    private long uInt32Sigfigs;

    private long uInt32snapLen;

    private long uInt32LinkType;

    private boolean isFlip = false;

    private byte[] mySourceByteArr = null;

    // use to determine if file was recorded on a big indian or a little indian
    private static final long MAGIC_NUMBER_FLIP = 0xd4c3b2a1L;
    private static final long MAGIC_NUMBER_DONT_FLIP = 0xa1b2c3d4L;

    /**
     * create pcap file header with defaults.
     */
    public PCapFileHeader() {
        uInt32MagicNum = MAGIC_NUMBER_DONT_FLIP;
        uShort16VersionMajor = 2;
        uShort16VersionMinor = 4;
        uInt32ThisTimeZone = 0;
        uInt32Sigfigs = 0;
        uInt32snapLen = 0xffff;
        uInt32LinkType = 1;
    }

    /**
     * read pcap header from stream.
     *
     * @param in
     * @throws IOException
     */
    public void readHeader(InputStream in) throws IOException {
        byte[] tmp = new byte[24];
        in.read(tmp);
        uInt32MagicNum = ByteUtils.getByteNetOrderTo_unit32(tmp, 0);
        uShort16VersionMajor = ByteUtils.getByteNetOrderTo_unit16(tmp, 4);
        uShort16VersionMinor = ByteUtils.getByteNetOrderTo_unit16(tmp, 6);
        uInt32ThisTimeZone = ByteUtils.getByteNetOrderTo_unit32(tmp, 8);
        uInt32Sigfigs = ByteUtils.getByteNetOrderTo_unit32(tmp, 12);
        uInt32snapLen = ByteUtils.getByteNetOrderTo_unit32(tmp, 16);
        uInt32LinkType = ByteUtils.getByteNetOrderTo_unit32(tmp, 20);

        if (uInt32MagicNum == MAGIC_NUMBER_DONT_FLIP) {
            isFlip = false;
        } else if (uInt32MagicNum == MAGIC_NUMBER_FLIP) {
            isFlip = true;
        } else {
            throw new IOException("Not a libcap file format");
        }

        if (isFlip) {
            uShort16VersionMajor = pcapRead16(uShort16VersionMajor);
            uShort16VersionMinor = pcapRead16(uShort16VersionMinor);
            uInt32ThisTimeZone = pcapRead32(uInt32ThisTimeZone);
            uInt32Sigfigs = pcapRead32(uInt32Sigfigs);
            uInt32snapLen = pcapRead32(uInt32snapLen);
            uInt32LinkType = pcapRead32(uInt32LinkType);
        }

        mySourceByteArr = tmp;
    }

    /**
     * @return the header in big indian order.
     */
    public byte[] getAsByteArray() {
        byte[] tmp = new byte[24];
        ByteUtils.setBigIndianInBytesArray(tmp, 0, uInt32MagicNum, 4);
        ByteUtils.setBigIndianInBytesArray(tmp, 4, uShort16VersionMajor, 2);
        ByteUtils.setBigIndianInBytesArray(tmp, 6, uShort16VersionMinor, 2);
        ByteUtils.setBigIndianInBytesArray(tmp, 8, uInt32ThisTimeZone, 4);
        ByteUtils.setBigIndianInBytesArray(tmp, 12, uInt32Sigfigs, 4);
        ByteUtils.setBigIndianInBytesArray(tmp, 16, uInt32snapLen, 4);
        ByteUtils.setBigIndianInBytesArray(tmp, 20, uInt32LinkType, 4);
        return tmp;
    }

    /**
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return "flip : " + isFlip + "\n" + "major : " + uShort16VersionMajor + "\n" + "minor : " + uShort16VersionMinor + "\n" + "time zone : " + Long.toHexString(uInt32ThisTimeZone) + "\n" + "sig figs : " + Long.toHexString(uInt32Sigfigs) + "\n" + "snap length : " + uInt32snapLen + "\n"
                + "link type : " + uInt32LinkType + "\n";
    }

    private long pcapRead32(long num) {
        long tmp = num;
        if (isFlip) {
            tmp = ((tmp & 0x000000FF) << 24) + ((tmp & 0x0000FF00) << 8) + ((tmp & 0x00FF0000) >> 8) + ((tmp & 0xFF000000) >> 24);

            return tmp;
        }
        return num;
    }

    private int pcapRead16(int num) {
        int tmp = num;
        if (isFlip) {
            tmp = ((tmp & 0x00FF) << 8) + ((tmp & 0xFF00) >> 8);
            return tmp;
        }
        return num;
    }

    public byte[] getSourceByteArr() {
        return mySourceByteArr;
    }

    public boolean isflip() {
        return isFlip;
    }

}
