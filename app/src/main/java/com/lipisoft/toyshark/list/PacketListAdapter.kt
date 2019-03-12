package com.lipisoft.toyshark.list

import android.annotation.SuppressLint
import android.os.AsyncTask
import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.ViewGroup
import com.lipisoft.toyshark.packet.Packet
import com.lipisoft.toyshark.R
import com.lipisoft.toyshark.util.DataConst.TCP
import com.lipisoft.toyshark.util.DataConst.UDP
import com.lipisoft.toyshark.util.PacketUtil
import java.net.InetAddress

import java.util.Date
import java.util.Locale

class PacketListAdapter(private val list: List<Packet>) :
        RecyclerView.Adapter<PacketInfoViewHolder>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): PacketInfoViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(
                R.layout.packet_info,
                parent,
                false
        )
        return PacketInfoViewHolder(view)
    }

    @SuppressLint("SetTextI18n")
    override fun onBindViewHolder(holder: PacketInfoViewHolder, position: Int) {
        val packet = list[position]

        val protocol = when (packet.protocol) {
            TCP -> "TCP"
            UDP -> "UDP"
            else -> ""
        }

        val time = Date().toString()
        val ip = PacketUtil.intToIPAddress(packet.ipHeader.destinationIP)
        val port = String.format(Locale.getDefault(), "%d", packet.destinationPort)
        val url = String(packet.buffer)

        holder.time.text = time
        holder.protocol.text = protocol
        holder.port.text = port
        holder.ip.text = ip
        holder.url.text = url

    }

    override fun getItemCount() = list.size

}
