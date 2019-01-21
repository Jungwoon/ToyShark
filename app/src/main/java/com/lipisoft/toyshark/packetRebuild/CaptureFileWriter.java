package com.lipisoft.toyshark.packetRebuild;

import java.io.IOException;

/**
 * Interface for writing capture file.<br>
 * There are many formats for capture files which may require
 * different handling, but this difference is not relevant when writing
 * a capture file for analyzing it packets.<br>
 * The interface provides the required abstraction.<br>
 * 
 * 
 * @author roni bar yanai
 *
 */
public interface CaptureFileWriter {
	/**
	 * write packet to file.
	 * @param packet - packet as byte array
	 * @param time - time in nano seconds.
	 * @return true for success.
	 * @throws IOException
	 */

	boolean addPacket(byte[] packet, long time) throws IOException;
	
	/**
	 * close the file, make sure data flushed to disk.
	 * (will happen automatically eventually, should always be called when we want
	 *   to use the created file in the code)
	 * @throws IOException 
	 */
	void close() throws IOException;
}
