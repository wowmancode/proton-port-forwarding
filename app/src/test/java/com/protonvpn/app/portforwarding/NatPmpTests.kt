/*
 * Copyright (c) 2026 Proton AG and contributors
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.protonvpn.app.portforwarding

import com.protonvpn.android.portforwarding.Datagram
import com.protonvpn.android.portforwarding.NatPmp
import com.protonvpn.android.portforwarding.NatPmpClient
import com.protonvpn.android.portforwarding.NatPmpException
import com.protonvpn.android.portforwarding.NatPmpTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import kotlin.test.assertFailsWith

class NatPmpTests {

    private val gateway = InetAddress.getByName("10.2.0.1")
    private val lanAttacker = InetAddress.getByName("192.168.1.66")

    private fun mapReply(op: Int, result: Int, internal: Int, external: Int, lifetime: Long, size: Int = 16) =
        ByteArray(size).also { b ->
            b[1] = (128 + op).toByte()
            b[2] = (result ushr 8).toByte(); b[3] = result.toByte()
            if (size >= 16) {
                b[8] = (internal ushr 8).toByte(); b[9] = internal.toByte()
                b[10] = (external ushr 8).toByte(); b[11] = external.toByte()
                b[12] = (lifetime ushr 24).toByte(); b[13] = (lifetime ushr 16).toByte()
                b[14] = (lifetime ushr 8).toByte(); b[15] = lifetime.toByte()
            }
        }

    private fun addressReply(ip: String) = ByteArray(12).also { b ->
        b[1] = 128.toByte()
        InetAddress.getByName(ip).address.copyInto(b, 8)
    }

    private class FakeTransport(vararg replies: Datagram?) : NatPmpTransport {
        private val queue = ArrayDeque(replies.toList())
        val sent = mutableListOf<ByteArray>()
        override fun send(data: ByteArray) { sent += data }
        override fun receive(timeoutMs: Int): Datagram? = queue.removeFirstOrNull()
        override fun close() = Unit
    }

    private fun tcp(bytes: ByteArray, requested: Int = 0) = NatPmp.parseMapping(bytes, NatPmp.Protocol.TCP, requested)

    @Test
    fun `valid mapping is accepted`() {
        val result = tcp(mapReply(2, 0, 51234, 51234, 60))
        assertTrue(result is NatPmp.ParseResult.Ok && result.value.externalPort == 51234)
    }

    @Test
    fun `malformed or unsafe replies are rejected`() {
        listOf(
            mapReply(1, 0, 51234, 51234, 60), // UDP reply for TCP request
            mapReply(2, 0, 51234, 51234, 60).copyOf(15), // truncated
            mapReply(2, 0, 51234, 51234, 60, size = 20), // oversized
            mapReply(2, 0, 22, 22, 60), // privileged port
            mapReply(2, 0, 50000, 50001, 60), // internal/external mismatch
            mapReply(2, 0, 50000, 50000, 0), // zero lifetime
            mapReply(2, 0, 50000, 50000, 0xFFFFFFFFL), // absurd lifetime
            mapReply(2, 2, 50000, 50000, 60), // refused
            mapReply(2, 0, 50000, 50000, 60).also { it[0] = 1 }, // bad version
        ).forEach { assertTrue(tcp(it) is NatPmp.ParseResult.Error) }
        assertTrue(tcp(mapReply(2, 0, 50001, 50001, 60), requested = 50000) is NatPmp.ParseResult.Error)
    }

    @Test
    fun `non-public gateway addresses are rejected`() {
        assertTrue(NatPmp.parsePublicAddress(addressReply("185.159.157.10")) is NatPmp.ParseResult.Ok)
        listOf("10.2.0.1", "192.168.0.1", "100.64.1.1", "0.0.0.0", "127.0.0.1").forEach {
            assertTrue(NatPmp.parsePublicAddress(addressReply(it)) is NatPmp.ParseResult.Error)
        }
    }

    @Test
    fun `spoofed replies are ignored and the real gateway reply is used`() {
        val spoof = mapReply(2, 0, 1080, 1080, 60)
        val transport = FakeTransport(
            Datagram(spoof, lanAttacker, 5351),
            Datagram(spoof, gateway, 5350),
            Datagram(byteArrayOf(0, 1, 2), gateway, 5351),
            Datagram(mapReply(2, 0, 40000, 40000, 60), gateway, 5351),
        )
        val client = NatPmpClient(transport, gateway)
        assertEquals(40000, client.map(NatPmp.Protocol.TCP, 0, 60).externalPort)
        assertEquals(3, client.rejectedDatagrams)
    }

    @Test
    fun `gateway refusal fails immediately without retrying`() {
        val transport = FakeTransport(Datagram(mapReply(2, 2, 0, 0, 0), gateway, 5351))
        assertFailsWith<NatPmpException> { NatPmpClient(transport, gateway).map(NatPmp.Protocol.TCP, 0, 60) }
        assertEquals(1, transport.sent.size)
    }

    @Test
    fun `no reply gives up after a bounded number of attempts`() {
        val transport = FakeTransport()
        assertFailsWith<NatPmpException> {
            NatPmpClient(transport, gateway, initialTimeoutMs = 1, maxAttempts = 5).map(NatPmp.Protocol.UDP, 0, 60)
        }
        assertEquals(5, transport.sent.size)
    }
}
