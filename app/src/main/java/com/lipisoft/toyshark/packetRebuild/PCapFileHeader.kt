package com.lipisoft.toyshark.packetRebuild

import com.lipisoft.toyshark.util.ByteUtils

/**
 * Class for holding libcap file header data structure.<br></br>
 * Each libcap start with this header.<br></br>
 *
 * @author roni bar yanai
 */
class PCapFileHeader {

    private val uInt32MagicNum: Long = 0xa1b2c3d4L
    private val uShort16VersionMajor: Int = 2
    private val uShort16VersionMinor: Int = 4
    private val uInt32ThisTimeZone: Long = 0
    private val uInt32Sig: Long = 0
    private val uInt32snapLen: Long = 0xffff
    private val uInt32LinkType: Long = 1

    companion object {
        const val HEADER_SIZE = 24
    }

    /**
     * @return the header in big indian order.
     */
    val asByteArray: ByteArray
        get() {
            val bytes = ByteArray(24)
            ByteUtils.setBigIndianInBytesArray(bytes, 0, uInt32MagicNum, 4)
            ByteUtils.setBigIndianInBytesArray(bytes, 4, uShort16VersionMajor.toLong(), 2)
            ByteUtils.setBigIndianInBytesArray(bytes, 6, uShort16VersionMinor.toLong(), 2)
            ByteUtils.setBigIndianInBytesArray(bytes, 8, uInt32ThisTimeZone, 4)
            ByteUtils.setBigIndianInBytesArray(bytes, 12, uInt32Sig, 4)
            ByteUtils.setBigIndianInBytesArray(bytes, 16, uInt32snapLen, 4)
            ByteUtils.setBigIndianInBytesArray(bytes, 20, uInt32LinkType, 4)
            return bytes
        }

    override fun toString(): String {
        return ("""flip : false
                major : $uShort16VersionMajor
                minor : $uShort16VersionMinor
                time zone : ${java.lang.Long.toHexString(uInt32ThisTimeZone)}
                sig figs : ${java.lang.Long.toHexString(uInt32Sig)}
                snap length : $uInt32snapLen
                link type : $uInt32LinkType
                """)
    }
}