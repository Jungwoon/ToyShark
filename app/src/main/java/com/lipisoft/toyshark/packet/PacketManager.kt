package com.lipisoft.toyshark.packet

import android.os.Handler
import android.os.Looper
import android.os.Message

import com.lipisoft.toyshark.list.PacketListAdapter

import java.util.ArrayList

enum class PacketManager {
    INSTANCE;

    companion object {
        const val PACKET = 0
    }

    val packetList = ArrayList<Packet>()
    private var adapter: PacketListAdapter? = null

    val handler: Handler = object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message?) {
            if (msg != null) {
                if (msg.what == PACKET) {
                    adapter!!.notifyDataSetChanged()
                }
            }
            super.handleMessage(msg)
        }
    }

    fun add(packet: Packet): Boolean {
        return packetList.add(packet)
    }

    fun setAdapter(adapter: PacketListAdapter) {
        this.adapter = adapter
    }

}
