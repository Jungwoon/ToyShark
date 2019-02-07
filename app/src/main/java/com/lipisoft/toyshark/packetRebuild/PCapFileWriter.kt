package com.lipisoft.toyshark.packetRebuild

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream

/**
 * Class for creating capture files in libcap format.<br></br>
 *
 *
 * if using java version less then 1.5 then the packet time resolution will
 * be in msec and no nanosec.<br></br>
 *
 * @author roni bar yanai
 * @since java 1.5
 */

class PCapFileWriter(file: File?, append: Boolean) : CaptureFileWriter() {

    companion object {
        const val MAX_PACKET_SIZE = 65356
        private const val DEFAULT_LIMIT = 100000000000L
    }

    // limit the file size
    private val myLimit = DEFAULT_LIMIT

    // the out stream
    private var outputStream: OutputStream? = null

    private var isOpened = false

    // used to calculate the packets time.
    private val myStartTime: Long

    // total ~bytes written so far.
    private var myTotalBytes: Long = 0


    /**
     * @return time stamp in nano seconds
     */
    private val nanoTime = System.nanoTime()

    /**
     * open new file
     *
     * @param file file
     * @throws IOException - on file creation failure.
     */

    constructor(file: File) : this(file, false)

    init {
        if (file == null) throw IllegalArgumentException("Got null file object")

        init(file, append)
        myStartTime = nanoTime
    }

    /**
     * open the out stream and write the cap header.
     *
     * @param file file
     * @throws IOException exception
     */
    @Throws(IOException::class)
    private fun init(file: File, append: Boolean) {
        val putHeader = !file.exists() || !append

        outputStream = FileOutputStream(file, append)

        // put hdr only if not appending or file not exits (new file).
        if (putHeader) {
            val hdr = PCapFileHeader()
            outputStream!!.write(hdr.asByteArray)
        }
        isOpened = true
        myTotalBytes += PCapFileHeader.HEADER_SIZE.toLong()
    }

    /**
     * add packet to already opened cap.
     * if close method was called earlier then will not add it.
     *
     * @param packet packet
     * @param time   - time offset in micro sec
     * @return true if packet added and false otherwise
     * @throws IOException exception
     * @throws IOException exception
     */
    @Throws(IOException::class)
    override fun addPacket(packet: ByteArray, time: Long): Boolean {

        if (!isOpened || myTotalBytes > myLimit) return false

        val pCapPacketHeader = PCapPacketHeader()

        pCapPacketHeader.setTimeMilliSec(time % 1000000)
        pCapPacketHeader.setTimeSec(time / 1000000L)
        pCapPacketHeader.setPacketLength(packet.size.toLong())
        pCapPacketHeader.setCapLength(packet.size.toLong())

        if (packet.size > MAX_PACKET_SIZE)
            throw IOException("Got illeagl packet size : " + packet.size)

        outputStream!!.write(pCapPacketHeader.asByteArray)
        outputStream!!.write(packet)

        myTotalBytes += (packet.size + PCapPacketHeader.HEADER_SIZE).toLong()

        return true


    }

    /**
     * add packet to alreay opened cap.
     * if close method was called earlier then will not add it.
     *
     * @param packet packet to store
     * @param offset offset
     * @param length length of packet
     * @param mTime   timestamp
     * @return success or not
     * @throws IOException exception
     */
    @Throws(IOException::class)
    fun addPacket(packet: ByteArray?, offset: Int, length: Int, mTime: Long): Boolean {
        var time = mTime
        val ethernetHeadLength = 14

        if (packet == null || !isOpened || myTotalBytes > myLimit)
            return false

        val pCapPacketHeader = PCapPacketHeader()

        if (time == 0L) {
            time = nanoTime - myStartTime // the gap since start in nano sec
        }

        pCapPacketHeader.setTimeMilliSec(time / 1000 % 1000000)
        pCapPacketHeader.setTimeSec(time / 1000000000L)

        // updated to use the real packet length
        pCapPacketHeader.setPacketLength((length + ethernetHeadLength).toLong())
        pCapPacketHeader.setCapLength((length + ethernetHeadLength).toLong())

        if (length > MAX_PACKET_SIZE)
            throw IOException("Got illeagl packet size : " + packet.size)

        outputStream!!.write(pCapPacketHeader.asByteArray)

        // added to write fake ethernet header
        outputStream!!.write(StubbedEthernetHeader.ethernetHeader)

        outputStream!!.write(packet, offset, length)

        // update to use real packet length and add in len of ethernet header
        myTotalBytes += (length + ethernetHeadLength + PCapPacketHeader.HEADER_SIZE).toLong()

        return true
    }


    /**
     * close file.
     * not reversible
     */
    override fun close() {
        if (isOpened && outputStream != null) {
            try {
                outputStream!!.close()
            } catch (e: IOException) {
                e.printStackTrace()
            }

            isOpened = false
            outputStream = null
        }
    }

}
