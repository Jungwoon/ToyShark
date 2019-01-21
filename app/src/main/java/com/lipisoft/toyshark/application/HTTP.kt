package com.lipisoft.toyshark.application

import android.util.Pair

/**
 * Created by Lipi on 2017. 3. 28..
 */

class HTTP(val httpHeaders: List<Pair<String, String>>, val body: ByteArray) : IApplication
