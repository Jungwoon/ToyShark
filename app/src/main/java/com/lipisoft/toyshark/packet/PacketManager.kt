package com.lipisoft.toyshark.packet

import android.os.Handler
import android.os.Looper
import android.os.Message

import com.lipisoft.toyshark.list.PacketListAdapter

import java.util.ArrayList

object PacketManager {
    const val PACKET = 0

    val packetList = ArrayList<Packet>()
    private var packetListAdapter: PacketListAdapter? = null

    val handler: Handler = object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message?) {
            if (message != null) {
                if (message.what == PACKET) {
                    packetListAdapter!!.notifyDataSetChanged()
                }
            }
            super.handleMessage(message)
        }
    }

    fun add(packet: Packet): Boolean {
        return packetList.add(packet)
    }

    fun setAdapter(packetListAdapter: PacketListAdapter) {
        this.packetListAdapter = packetListAdapter
    }

}