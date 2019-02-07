package com.lipisoft.toyshark.list

import android.annotation.SuppressLint
import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.ViewGroup

import com.lipisoft.toyshark.packet.Packet
import com.lipisoft.toyshark.R
import com.lipisoft.toyshark.util.PacketUtil

import java.util.Date
import java.util.Locale

class PacketListAdapter(private val list: List<Packet>) : RecyclerView.Adapter<PacketInfoViewHolder>() {

    companion object {
        private const val TCP: Byte = 6
        private const val UDP: Byte = 17
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): PacketInfoViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.packet_info, parent, false)
        return PacketInfoViewHolder(view)
    }

    @SuppressLint("SetTextI18n")
    override fun onBindViewHolder(holder: PacketInfoViewHolder, position: Int) {
        val packet = list[position]
        val time = holder.time
        val protocol = holder.protocol
        val address = holder.address
        val port = holder.port

        time.text = Date().toString()
        val protocolType = packet.protocol

        when (protocolType) {
            TCP -> protocol.text = "TCP"
            UDP -> protocol.text = "UDP"
            else -> protocol.text = ""
        }

        address.text = PacketUtil.intToIPAddress(packet.ipHeader.destinationIP)
        port.text = String.format(Locale.getDefault(), "%d", packet.destinationPort)
    }

    override fun getItemCount() = list.size

}
