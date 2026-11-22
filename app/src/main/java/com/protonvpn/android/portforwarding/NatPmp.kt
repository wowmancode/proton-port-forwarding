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

package com.protonvpn.android.portforwarding

import java.net.Inet4Address
import java.net.InetAddress

/**
 * Minimal, strict NAT-PMP (RFC 6886) client used for Proton VPN port forwarding.
 *
 * Pure Kotlin/JVM, no Android dependencies, so it can be unit tested in isolation.
 *
 * Security properties:
 *  - Replies are accepted only from the expected gateway address and port 5351 (anti-spoofing; the
 *    transport is additionally expected to be a connected socket bound to the VPN network).
 *  - Replies are parsed strictly: exact length, version 0, matching opcode, success result code,
 *    matching internal port, sane external port and lifetime. Anything else is rejected.
 *  - Retries are bounded (RFC 6886 style 250ms doubling, capped) so a missing gateway can't cause
 *    unbounded traffic or hangs.
 */
object NatPmp {
    const val SERVER_PORT = 5351
    const val VERSION: Byte = 0

    const val OP_PUBLIC_ADDRESS = 0
    const val OP_MAP_UDP = 1
    const val OP_MAP_TCP = 2
    private const val RESPONSE_FLAG = 128

    const val RESULT_SUCCESS = 0

    /** Ports below this are never accepted as a forwarded port. */
    const val MIN_ACCEPTED_EXTERNAL_PORT = 1024

    /** Upper bound we accept for a lifetime; protects against absurd server values. */
    const val MAX_ACCEPTED_LIFETIME_S = 7200L

    private const val PUBLIC_ADDRESS_RESPONSE_SIZE = 12
    private const val MAP_RESPONSE_SIZE = 16

    enum class Protocol(val opcode: Int) { UDP(OP_MAP_UDP), TCP(OP_MAP_TCP) }

    fun publicAddressRequest(): ByteArray = byteArrayOf(VERSION, OP_PUBLIC_ADDRESS.toByte())

    fun mapRequest(protocol: Protocol, internalPort: Int, suggestedExternalPort: Int, lifetimeS: Long): ByteArray {
        require(internalPort in 0..65535) { "internalPort out of range" }
        require(suggestedExternalPort in 0..65535) { "externalPort out of range" }
        require(lifetimeS in 0..0xFFFFFFFFL) { "lifetime out of range" }
        val b = ByteArray(12)
        b[0] = VERSION
        b[1] = protocol.opcode.toByte()
        // b[2..3] reserved = 0
        putU16(b, 4, internalPort)
        putU16(b, 6, suggestedExternalPort)
        putU32(b, 8, lifetimeS)
        return b
    }

    sealed class ParseResult<out T> {
        data class Ok<T>(val value: T) : ParseResult<T>()
        data class Error(val reason: String) : ParseResult<Nothing>()
    }

    data class PublicAddress(val address: Inet4Address, val epochS: Long)

    data class Mapping(
        val protocol: Protocol,
        val internalPort: Int,
        val externalPort: Int,
        val lifetimeS: Long,
        val epochS: Long,
    )

    fun parsePublicAddress(data: ByteArray): ParseResult<PublicAddress> {
        if (data.size != PUBLIC_ADDRESS_RESPONSE_SIZE)
            return ParseResult.Error("bad public address reply size ${data.size}")
        headerError(data, OP_PUBLIC_ADDRESS)?.let { return ParseResult.Error(it) }
        val epoch = getU32(data, 4)
        val ip = InetAddress.getByAddress(data.copyOfRange(8, 12)) as Inet4Address
        if (ip.isAnyLocalAddress || ip.isLoopbackAddress || ip.isSiteLocalAddress ||
            ip.isLinkLocalAddress || ip.isMulticastAddress || isCgnat(ip))
            return ParseResult.Error("gateway returned a non-public address")
        return ParseResult.Ok(PublicAddress(ip, epoch))
    }

    /**
     * @param requestedInternalPort the internal port we put in the request. Proton's gateway always
     * reports internal == external, so when we asked for 0 we accept internal == external only.
     */
    fun parseMapping(data: ByteArray, protocol: Protocol, requestedInternalPort: Int): ParseResult<Mapping> {
        if (data.size != MAP_RESPONSE_SIZE)
            return ParseResult.Error("bad mapping reply size ${data.size}")
        headerError(data, protocol.opcode)?.let { return ParseResult.Error(it) }
        val epoch = getU32(data, 4)
        val internal = getU16(data, 8)
        val external = getU16(data, 10)
        val lifetime = getU32(data, 12)
        if (requestedInternalPort != 0 && internal != requestedInternalPort)
            return ParseResult.Error("internal port mismatch")
        if (internal != external)
            return ParseResult.Error("internal/external port mismatch")
        if (external < MIN_ACCEPTED_EXTERNAL_PORT)
            return ParseResult.Error("unsafe external port $external")
        if (lifetime <= 0L || lifetime > MAX_ACCEPTED_LIFETIME_S)
            return ParseResult.Error("bad lifetime $lifetime")
        return ParseResult.Ok(Mapping(protocol, internal, external, lifetime, epoch))
    }

    private fun headerError(data: ByteArray, requestOpcode: Int): String? {
        if (data[0] != VERSION) return "unsupported version ${data[0]}"
        val op = data[1].toInt() and 0xFF
        if (op != RESPONSE_FLAG + requestOpcode) return "unexpected opcode $op"
        val result = getU16(data, 2)
        if (result != RESULT_SUCCESS) return "gateway result code $result (${resultName(result)})"
        return null
    }

    fun resultName(code: Int) = when (code) {
        0 -> "success"
        1 -> "unsupported version"
        2 -> "not authorized/refused"
        3 -> "network failure"
        4 -> "out of resources"
        5 -> "unsupported opcode"
        else -> "unknown"
    }

    private fun isCgnat(ip: Inet4Address): Boolean {
        val b = ip.address
        return (b[0].toInt() and 0xFF) == 100 && (b[1].toInt() and 0xC0) == 64
    }

    private fun putU16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 8).toByte(); b[off + 1] = v.toByte()
    }

    private fun putU32(b: ByteArray, off: Int, v: Long) {
        b[off] = (v ushr 24).toByte(); b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte(); b[off + 3] = v.toByte()
    }

    private fun getU16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun getU32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFF) shl 24) or ((b[off + 1].toLong() and 0xFF) shl 16) or
            ((b[off + 2].toLong() and 0xFF) shl 8) or (b[off + 3].toLong() and 0xFF)
}

/** One received UDP datagram together with its source. */
class Datagram(val data: ByteArray, val source: InetAddress, val sourcePort: Int)

/**
 * Transport abstraction. The Android implementation must be a UDP socket bound to the VPN network and
 * connected to the gateway, so packets never leave via Wi-Fi/mobile data.
 */
interface NatPmpTransport : AutoCloseable {
    fun send(data: ByteArray)
    /** @return a datagram or null on timeout. */
    fun receive(timeoutMs: Int): Datagram?
}

class NatPmpException(message: String) : Exception(message)

class NatPmpClient(
    private val transport: NatPmpTransport,
    private val gateway: InetAddress,
    private val initialTimeoutMs: Int = 250,
    private val maxAttempts: Int = 5, // 250+500+1000+2000+4000 ms worst case
    private val clockMs: () -> Long = System::currentTimeMillis,
) {
    /** Number of datagrams dropped because they failed source/format validation. */
    var rejectedDatagrams: Int = 0
        private set

    fun publicAddress(): NatPmp.PublicAddress =
        exchange(NatPmp.publicAddressRequest()) { NatPmp.parsePublicAddress(it) }

    fun map(protocol: NatPmp.Protocol, port: Int, lifetimeS: Long): NatPmp.Mapping =
        exchange(NatPmp.mapRequest(protocol, port, port, lifetimeS)) { NatPmp.parseMapping(it, protocol, port) }

    /** Best effort removal of a mapping (lifetime 0). Errors are ignored by design. */
    fun unmap(protocol: NatPmp.Protocol, port: Int) {
        runCatching { transport.send(NatPmp.mapRequest(protocol, port, 0, 0)) }
    }

    private fun <T> exchange(request: ByteArray, parse: (ByteArray) -> NatPmp.ParseResult<T>): T {
        var timeout = initialTimeoutMs
        var lastError = "no reply from gateway"
        repeat(maxAttempts) {
            transport.send(request)
            val deadline = clockMs() + timeout
            while (true) {
                val remaining = (deadline - clockMs()).toInt()
                if (remaining <= 0) break
                val datagram = transport.receive(remaining) ?: break
                if (datagram.source != gateway || datagram.sourcePort != NatPmp.SERVER_PORT) {
                    rejectedDatagrams++
                    continue // Ignore spoofed / unrelated packets, keep waiting.
                }
                when (val result = parse(datagram.data)) {
                    is NatPmp.ParseResult.Ok -> return result.value
                    is NatPmp.ParseResult.Error -> {
                        // A well-formed refusal from the real gateway is final; a malformed packet is ignored.
                        if (result.reason.startsWith("gateway result code")) throw NatPmpException(result.reason)
                        rejectedDatagrams++
                        lastError = result.reason
                    }
                }
            }
            timeout *= 2
        }
        throw NatPmpException(lastError)
    }
}
