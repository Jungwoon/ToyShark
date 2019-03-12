/*
 *  Copyright 2016 Lipi C.H. Lee
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
package com.lipisoft.toyshark

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Bundle
import android.os.Environment
import android.support.v7.app.AppCompatActivity
import android.support.v7.widget.DividerItemDecoration
import android.support.v7.widget.LinearLayoutManager
import android.support.v7.widget.RecyclerView
import android.util.Log
import com.lipisoft.toyshark.list.PacketListAdapter
import java.net.NetworkInterface
import java.util.Collections
import com.lipisoft.toyshark.packet.PacketManager

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    /** check whether network is connected or not
     * @return boolean
     */
    private val isConnectedToInternet: Boolean
        get() {
            val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val networkInfo = connectivity.activeNetworkInfo
            return networkInfo != null && networkInfo.isConnected
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.packet_list)

        val recyclerView = findViewById<RecyclerView>(R.id.packet_list_recycler_view)
        recyclerView.addItemDecoration(DividerItemDecoration(this, DividerItemDecoration.VERTICAL))
        recyclerView.setHasFixedSize(true)
        recyclerView.layoutManager = LinearLayoutManager(this)

        val adapter = PacketListAdapter(PacketManager.packetList)
        PacketManager.setAdapter(adapter)
        recyclerView.adapter = adapter

        checkVpnPermission()
    }

    private fun checkVpnPermission() {
        if (isConnectedToInternet)
            startVPN()
        else {
            showInfoDialog(resources.getString(R.string.app_name),
                    resources.getString(R.string.no_network_information))
        }
    }

    /**
     * Launch intent for user approval of VPN connection
     */
    private fun startVPN() {
        try {
            if (!checkForActiveInterface("tun0")) {
                // get user permission for VPN
                val intent = VpnService.prepare(this)
                if (intent != null) {
                    Log.d(TAG, "ask user for VPN permission")
                    startActivityForResult(intent, 0)
                } else {
                    Log.d(TAG, "already have VPN permission")
                    onActivityResult(0, RESULT_OK, null)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception checking network interfaces :" + e.message)
            e.printStackTrace()
        }

    }

    /**
     * check a network interface by name
     *
     * @param networkInterfaceName Network interface Name on Linux, for example tun0
     * @return true if interface exists and is active
     * @throws Exception throws Exception
     */
    @Throws(Exception::class)
    private fun checkForActiveInterface(networkInterfaceName: String): Boolean {
        val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
        for (networkInterface in interfaces) {
            if (networkInterface.name == networkInterfaceName) {
                return networkInterface.isUp
            }
        }
        return false
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        Log.i(TAG, "onActivityResult(resultCode:  $resultCode)")
        when (resultCode) {
            RESULT_OK -> {
                val captureVpnServiceIntent = Intent(applicationContext, ToySharkVPNService::class.java)
                captureVpnServiceIntent.putExtra("TRACE_DIR", Environment.getExternalStorageDirectory().path + "/ToyShark")
                startService(captureVpnServiceIntent)
            }
            RESULT_CANCELED -> showVPNRefusedDialog()
            else -> return
        }
    }

    /**
     * Show dialog to educate the user about VPN trust
     * abort app if user chooses to quit
     * otherwise relaunch the startVPN()
     */
    private fun showVPNRefusedDialog() {
        AlertDialog.Builder(this)
                .setTitle("Usage Alert")
                .setMessage("You must trust the ToyShark in order to run a VPN based trace.")
                .setPositiveButton(getString(R.string.try_again)) { _, _ -> startVPN() }
                .setNegativeButton(getString(R.string.quit)) { _, _ -> finish() }
                .show()

    }

    /**
     * @param title Title in Dialog
     * @param message Message in Dialog
     */
    private fun showInfoDialog(title: String, message: String) {
        AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton(getString(android.R.string.ok)) { _, _ ->
                    finish()
                }
                .show()
    }

}
