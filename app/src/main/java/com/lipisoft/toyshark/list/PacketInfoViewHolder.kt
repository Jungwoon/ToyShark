package com.lipisoft.toyshark.list

import android.support.v7.widget.RecyclerView
import android.view.View
import android.widget.TextView

import com.lipisoft.toyshark.R

class PacketInfoViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
    val time: TextView = itemView.findViewById(R.id.time)
    val protocol: TextView = itemView.findViewById(R.id.protocol)
    val port: TextView = itemView.findViewById(R.id.port)
    val ip: TextView = itemView.findViewById(R.id.ip)
    val url: TextView = itemView.findViewById(R.id.packet)
}
