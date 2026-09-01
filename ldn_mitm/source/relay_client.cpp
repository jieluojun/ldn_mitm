/*
 * Copyright (c) 2018 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "relay_client.hpp"
#include "debug.hpp"
#include "nifm_manager.hpp"
#include "session_registry.hpp"
#include "ldnmitm_config.hpp"
#include "tcp_relay.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <sys/time.h>
#include <atomic>
#include <mutex>
#include <cstdio>

namespace ams::mitm::ldn::relay {

    namespace {
        /* lan-play relay message types (switch-lan-play/src/lan-client.c). */
        constexpr u8 TypeKeepalive = 0x00;
        constexpr u8 TypeIpv4      = 0x01;
        constexpr u8 TypePing      = 0x02;
        constexpr u8 TypeIpv4Frag  = 0x03;
        /* ldn_mitm extension (tools/relay_server.py): [u32 BE session token]. */
        constexpr u8 TypeScope     = 0x20;

        /* IP header id of our wrapped frames; the receiver dispatches on it. */
        constexpr u16 IpIdControl = 0x4243;   /* LANDiscovery packets */
        constexpr u16 IpIdGame    = 0x474D;   /* addressed by real IPs */
        constexpr u16 IpIdGameV2  = 0x474E;   /* addressed by vsrc, real IPs in the shim */
        /* IpIdGameV2 shim: real src + real dst (BE) ahead of the game payload. */
        constexpr size_t GameShimLen = 8;

        /* 1500 MTU minus IP/UDP headers. */
        constexpr size_t MaxWrapPayload = 1472;
        constexpr size_t SingleFrameMax = 1500;

        /* lan-play IPV4_FRAG geometry; the receiver's completion mask is 8 bits. */
        constexpr u16 FragPmtu     = 1024;
        constexpr size_t FragMaxParts = 8;
        constexpr size_t MaxWrappedPacket = 20 + 8 + MaxWrapPayload + GameShimLen;
        static_assert((MaxWrappedPacket + FragPmtu - 1) / FragPmtu <= FragMaxParts);

        u32 Be32(const u8 *p) {
            return (static_cast<u32>(p[0]) << 24) | (static_cast<u32>(p[1]) << 16) |
                   (static_cast<u32>(p[2]) << 8)  | p[3];
        }

        u16 IpChecksum(const u8 *d, size_t n) {
            u32 s = 0;
            for (size_t i = 0; i + 1 < n; i += 2) {
                s += (static_cast<u32>(d[i]) << 8) | d[i + 1];
            }
            if (n & 1) {
                s += static_cast<u32>(d[n - 1]) << 8;
            }
            while (s >> 16) {
                s = (s & 0xffff) + (s >> 16);
            }
            return static_cast<u16>(~s & 0xffff);
        }

        struct Server { char name[ServerNameLen]; char host[64]; u32 ip; u16 port; };
        Server g_servers[MaxServers];
        int g_count = 0;
        std::atomic_int  g_selected{0};
        std::atomic_bool g_enabled{false};
        /* Low 16 bits of our virtual address 10.13.x.x; 0 = unassigned. */
        std::atomic<u16> g_client_id{0};

        /* Where the id came from. 0 = assigned before this feature existed,
           1 = derived from this console's LAN address, 2 = random fallback,
           3 = rotated away from the derived value to dodge a stale relay
           session that kept swallowing the echo. */
        constexpr int IdSourceUnknown  = 0;
        constexpr int IdSourceHardware = 1;
        constexpr int IdSourceRandom   = 2;
        constexpr int IdSourceRotated  = 3;
        std::atomic_int g_id_source{IdSourceUnknown};

        /* Index of the server the currently open transport is connected to;
           -1 until a transport opens. Compared against g_selected so the
           overlay never shows one server's reading under another's name. */
        std::atomic_int g_active_server{-1};

        /* Defined next to EnsureClientId() below. */
        bool DeriveIdFromHardware(u16 *out);
        void RefreshIdSource();

        /* Relay link latency: PING round-trip time in ms. 0 = not measured yet.
           Only an echo of the ping we are still waiting on updates it. */
        struct LatencyState {
            std::atomic<u32> ms{0};
            std::atomic<int> waiting{0};
            std::atomic<s64> pending_ms{0};
        };
        LatencyState g_latency;

        /* Guards relay.cfg I/O and its buffers. */
        constinit os::SdkMutex g_config_mutex;
        constexpr size_t ConfigCap = 4096;
        char g_config_buf[ConfigCap];
        char g_config_out[ConfigCap + 128];
    }

    namespace {
        const char *DirectiveValue(const char *l, const char *name) {
            const size_t n = std::strlen(name);
            if (std::strncmp(l, name, n) != 0) {
                return nullptr;
            }
            const char c = l[n];
            if (c != '\0' && c != '=' && c != ' ' && c != '\t') {
                return nullptr;
            }
            const char *v = l + n;
            while (*v == '=' || *v == ' ' || *v == '\t') { v++; }
            return v;
        }

        bool IsDirectiveLine(const char *l) {
            return DirectiveValue(l, "enabled")   != nullptr ||
                   DirectiveValue(l, "broadcast") != nullptr ||
                   DirectiveValue(l, "selected")  != nullptr ||
                   DirectiveValue(l, "id")        != nullptr;
        }

        /* Reserved: 0, x.0, x.255, and 37.x (common hand-picked lan-play range). */
        bool BadClientId(u16 id) {
            return id == 0 || (id & 0xFF) == 0xFF || (id & 0xFF) == 0x00 || (id >> 8) == 37;
        }

        enum class ConfigRead { Missing, Ok, Error, TooLarge };

        /* Requires g_config_mutex. */
        ConfigRead ReadConfigFile(char *buf, size_t cap) {
            buf[0] = '\0';
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Read))) {
                return ConfigRead::Missing;
            }
            ConfigRead res = ConfigRead::Error;
            s64 size = 0;
            if (R_SUCCEEDED(fs::GetFileSize(std::addressof(size), f)) && size >= 0) {
                const bool fits = static_cast<size_t>(size) < cap;
                const size_t n = fits ? static_cast<size_t>(size) : cap - 1;
                if (n == 0 || R_SUCCEEDED(fs::ReadFile(f, 0, buf, n))) {
                    buf[n] = '\0';
                    res = fits ? ConfigRead::Ok : ConfigRead::TooLarge;
                }
            }
            fs::CloseFile(f);
            return res;
        }
    }

    void LoadConfig() {
        /* Format: docs/relay.cfg.example. */
        std::scoped_lock lk(g_config_mutex);
        g_count = 0;
        g_selected = 0;
        g_enabled = false;
        g_client_id = 0;
        char pending_selected[ServerNameLen] = {};

        char *buf = g_config_buf;
        if (ReadConfigFile(buf, ConfigCap) == ConfigRead::TooLarge) {
            LogFormat("relay: %s exceeds %zu bytes, reading the start only", RelayConfigPath, ConfigCap - 1);
        }

        char *save = nullptr;
        for (char *line = strtok_r(buf, "\r\n", std::addressof(save));
             line != nullptr;
             line = strtok_r(nullptr, "\r\n", std::addressof(save))) {
            while (*line == ' ' || *line == '\t') { line++; }
            if (*line == '#' || *line == '\0') {
                continue;
            }
            if (const char *v = DirectiveValue(line, "enabled")) {
                g_enabled = (std::atoi(v) != 0);
                continue;
            }
            if (const char *v = DirectiveValue(line, "broadcast")) {
                LdnConfig::setBroadcastRelay(std::atoi(v) != 0);
                continue;
            }
            if (const char *v = DirectiveValue(line, "id")) {
                const long n = std::strtol(v, nullptr, 10);
                if (n > 0 && n < 0xFFFF && !BadClientId(static_cast<u16>(n))) {
                    g_client_id = static_cast<u16>(n);
                }
                continue;
            }
            if (const char *v = DirectiveValue(line, "selected")) {
                std::strncpy(pending_selected, v, sizeof(pending_selected) - 1);
                continue;
            }
            if (g_count >= MaxServers) {
                continue;
            }
            char name[ServerNameLen] = {};
            char addr[64] = {};
            if (std::sscanf(line, "%31s %63s", name, addr) < 2) {
                if (std::sscanf(line, "%63s", addr) < 1) {
                    continue;
                }
                std::strncpy(name, addr, sizeof(name) - 1);
            }

            unsigned port = 11451;
            char *colon = std::strchr(addr, ':');
            if (colon != nullptr) {
                *colon = '\0';
                port = static_cast<unsigned>(std::atoi(colon + 1));
            }
            if (addr[0] == '\0' || port == 0 || port > 65535) {
                continue;
            }
            unsigned a = 0, b = 0, c = 0, d = 0;
            u32 ip = 0;
            if (std::sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
                a <= 255 && b <= 255 && c <= 255 && d <= 255) {
                ip = (a << 24) | (b << 16) | (c << 8) | d;
            }

            Server &s = g_servers[g_count];
            std::strncpy(s.name, name, sizeof(s.name) - 1);
            s.name[sizeof(s.name) - 1] = '\0';
            std::strncpy(s.host, addr, sizeof(s.host) - 1);
            s.host[sizeof(s.host) - 1] = '\0';
            s.ip   = ip;
            s.port = static_cast<u16>(port);
            g_count++;
        }

        for (char *e = pending_selected + std::strlen(pending_selected);
             e > pending_selected && (e[-1] == ' ' || e[-1] == '\t'); ) {
            *--e = '\0';
        }
        if (pending_selected[0] != '\0') {
            for (int i = 0; i < g_count; i++) {
                if (std::strcmp(g_servers[i].name, pending_selected) == 0) {
                    g_selected = i;
                    break;
                }
            }
        }
        LogFormat("relay: loaded %d server(s), selected %d", g_count, g_selected.load());

        /* The id may have been cached in relay.cfg by an earlier boot; work
           out how it relates to this console's current LAN address so the
           overlay can report whether the address is stable. */
        RefreshIdSource();
    }

    namespace {
        void PersistConfig() {
            std::scoped_lock lk(g_config_mutex);
            char *buf = g_config_buf;
            char *out = g_config_out;
            constexpr size_t OutCap = sizeof(g_config_out);

            switch (ReadConfigFile(buf, ConfigCap)) {
                case ConfigRead::Missing:
                case ConfigRead::Ok:
                    break;
                case ConfigRead::TooLarge:
                    LogFormat("relay: not persisting settings, %s exceeds %zu bytes", RelayConfigPath, ConfigCap - 1);
                    return;
                case ConfigRead::Error:
                    LogFormat("relay: not persisting settings, %s unreadable", RelayConfigPath);
                    return;
            }

            size_t pos = static_cast<size_t>(std::snprintf(out, OutCap, "enabled=%d\nbroadcast=%d\n",
                g_enabled.load() ? 1 : 0, LdnConfig::getBroadcastRelay() ? 1 : 0));
            if (const u16 id = g_client_id.load(); id != 0) {
                pos += static_cast<size_t>(std::snprintf(out + pos, OutCap - pos,
                    "id=%u\n", id));
            }
            const int sel = g_selected.load();
            if (sel >= 0 && sel < g_count) {
                pos += static_cast<size_t>(std::snprintf(out + pos, OutCap - pos,
                    "selected=%s\n", g_servers[sel].name));
            }

            char *save = nullptr;
            for (char *line = strtok_r(buf, "\r\n", std::addressof(save));
                 line != nullptr;
                 line = strtok_r(nullptr, "\r\n", std::addressof(save))) {
                const char *p = line;
                while (*p == ' ' || *p == '\t') { p++; }
                if (IsDirectiveLine(p)) {
                    continue;
                }
                const size_t need = std::strlen(line) + 1;
                if (pos + need >= OutCap) {
                    LogFormat("relay: not persisting settings, rewritten config too large");
                    return;
                }
                std::memcpy(out + pos, line, need - 1);
                out[pos + need - 1] = '\n';
                pos += need;
            }

            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) {
                if (R_FAILED(fs::CreateFile(RelayConfigPath, 0)) ||
                    R_FAILED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) {
                    LogFormat("relay: persisting settings failed (open)");
                    return;
                }
            }
            fs::SetFileSize(f, 0);
            if (R_FAILED(fs::WriteFile(f, 0, out, pos, fs::WriteOption::Flush))) {
                LogFormat("relay: persisting settings failed (write)");
            }
            fs::CloseFile(f);
        }

        /* Stable hardware-derived id source.
           The LAN address is a good fingerprint: two consoles can never hold
           the same one at the same time, and it survives reboots as long as
           DHCP keeps handing out the same lease. Random is only the last
           resort, because two consoles drawing from the same 16-bit space
           collide about once in 60000 pairs -- and a collision shows up as
           "room is visible but joining fails", which is very hard to debug. */
        bool DeriveIdFromHardware(u16 *out) {
            u32 ip = 0;
            if (R_FAILED(nifmGetCurrentIpAddress(&ip))) {
                return false;
            }
            ip = ntohl(ip);
            if (ip == 0) {
                return false;
            }
            /* Cheap 32 -> 16 fold; good enough to keep distinct LAN
               addresses distinct after the reserved values are excluded. */
            u32 h = ip * 2654435761u;
            h ^= h >> 13;
            h *= 40503u;
            u16 id = static_cast<u16>(h ^ (h >> 16));
            if (BadClientId(id)) {
                id ^= 0x5A5Au;
            }
            if (BadClientId(id)) {
                return false;
            }
            *out = id;
            return true;
        }

        /* Classify the id we are currently using. Called on every config load,
           not only when a fresh id is drawn: a cached id that still matches
           what this console's LAN address derives is just as stable, and the
           overlay should say so after every reboot. */
        void RefreshIdSource() {
            const u16 id = g_client_id.load();
            if (id == 0) {
                g_id_source = IdSourceUnknown;
                return;
            }
            u16 hw = 0;
            if (!DeriveIdFromHardware(std::addressof(hw))) {
                /* No usable LAN address: the id must have come from the
                   random fallback (or predates this feature). */
                g_id_source = IdSourceRandom;
                return;
            }
            g_id_source = (hw == id) ? IdSourceHardware : IdSourceUnknown;
        }

        u16 EnsureClientId() {
            u16 id = g_client_id.load();
            if (id == 0) {
                u16 fresh = 0;
                bool from_hw = DeriveIdFromHardware(std::addressof(fresh));
                if (!from_hw) {
                    do {
                        os::GenerateRandomBytes(std::addressof(fresh), sizeof(fresh));
                    } while (BadClientId(fresh));
                }
                u16 expected = 0;
                if (g_client_id.compare_exchange_strong(expected, fresh)) {
                    id = fresh;
                    /* Persist either way. When the value came from hardware
                       the write is only a cache, so a read-only SD card still
                       yields the same address on every boot. */
                    PersistConfig();
                    RefreshIdSource();
                    LogFormat("relay: assigned virtual address 10.13.%u.%u (%s)",
                              (id >> 8) & 0xff, id & 0xff, from_hw ? "hardware" : "random");
                } else {
                    id = expected;
                }
            }
            return id;
        }
    }

    void PersistSettings()    { PersistConfig(); }

    bool IsEnabled()          { return g_enabled.load() && g_count > 0; }
    void SetRelayEnabled(bool on) { g_enabled = on; PersistConfig(); }
    bool GetRelayEnabled()    { return g_enabled.load(); }

    int  ServerCount()        { return g_count; }
    const char *ServerName(int i) { return (i >= 0 && i < g_count) ? g_servers[i].name : ""; }

    int  SelectedServer()     { return g_selected.load(); }
    void SelectServer(int i)  {
        if (i < 0 || i >= g_count) {
            return;
        }
        g_selected = i;
        /* The reading belonged to the previous server. Field logs showed a
           server that never answered a ping still displaying the previous
           server's 81ms, which is worse than showing nothing. */
        g_latency.ms = 0;
        g_latency.waiting = 0;
        PersistConfig();
    }

    /* Which server the open transport is actually talking to. Selecting a
       different server only rewrites the config; the socket keeps talking to
       the old host until it is reopened, so this is what the latency reading
       must be validated against. -1 = no transport open yet. */
    int  ActiveServer()       { return g_active_server.load(); }

    u32  ServerIp() {
        const int i = g_selected.load();
        return (i >= 0 && i < g_count) ? g_servers[i].ip : 0;
    }
    const char *ServerHost() {
        const int i = g_selected.load();
        return (i >= 0 && i < g_count) ? g_servers[i].host : "";
    }
    u16  ServerPort() {
        const int i = g_selected.load();
        return (i >= 0 && i < g_count) ? g_servers[i].port : 0;
    }

    int RelayGetIdSource() {
        return g_id_source.load();
    }

    u32 RelayGetLocalIp() {
        u32 ip = 0;
        if (R_FAILED(nifmGetCurrentIpAddress(&ip))) {
            return 0;
        }
        return ntohl(ip);
    }

    bool IsSessionPeer(u32 ip) {
        SessionRegistry::Snapshot snap;
        SessionRegistry::Get(std::addressof(snap));
        if (!snap.active) {
            return false;
        }
        for (int i = 0; i < snap.peer_count; i++) {
            if (snap.peer_ips[i] == ip) {
                return true;
            }
        }
        return false;
    }

    /* Bridge sends run under g_bridge_mutex, so a transport is unused once
       unpublished. The most recently opened one serves bridge sends. */
    namespace {
        constexpr int MaxBridged = 4;
        constinit os::SdkMutex g_bridge_mutex;
        constinit RelayTransport *g_bridged[MaxBridged] = {};
        constinit int g_bridged_count = 0;

        /* Requires g_bridge_mutex. */
        RelayTransport *BridgeTarget() {
            return g_bridged_count > 0 ? g_bridged[g_bridged_count - 1] : nullptr;
        }

        void BridgePublish(RelayTransport *t) {
            std::scoped_lock lk(g_bridge_mutex);
            if (g_bridged_count >= MaxBridged) {
                LogFormat("relay: bridge full, transport not published");
                return;
            }
            g_bridged[g_bridged_count++] = t;
        }

        void BridgeUnpublish(RelayTransport *t) {
            std::scoped_lock lk(g_bridge_mutex);
            for (int i = 0; i < g_bridged_count; i++) {
                if (g_bridged[i] == t) {
                    for (int j = i + 1; j < g_bridged_count; j++) {
                        g_bridged[j - 1] = g_bridged[j];
                    }
                    g_bridged[--g_bridged_count] = nullptr;
                    return;
                }
            }
        }
    }

    int BridgeSendGameBroadcast(const void *payload, size_t len, u16 dport) {
        std::scoped_lock lk(g_bridge_mutex);
        RelayTransport *t = BridgeTarget();
        return t != nullptr ? t->SendGameBroadcast(payload, len, dport) : -1;
    }

    int BridgeSendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip) {
        std::scoped_lock lk(g_bridge_mutex);
        RelayTransport *t = BridgeTarget();
        return t != nullptr ? t->SendGameUnicast(payload, len, dport, dst_ip) : -1;
    }

    u32 BridgeSelfIp() {
        std::scoped_lock lk(g_bridge_mutex);
        RelayTransport *t = BridgeTarget();
        return t != nullptr ? t->RealIp() : 0;
    }

    u32 RelayTransport::ResolveHostname(const char *host) {
        if (host == nullptr || host[0] == '\0') {
            return 0;
        }
        u32 a = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
        nifmGetCurrentIpConfigInfo(&a, &mask, &gw, &dns1, &dns2);

        struct sockaddr_in srv = {};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(53);
        srv.sin_addr.s_addr = (dns1 != 0) ? dns1 : htonl(0x08080808u);

        const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            return 0;
        }
        if (m_have_req) {
            nifmRequestRegisterSocketDescriptor(&m_req, fd);
        }
        struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        auto cleanup = [&]() {
            if (m_have_req) { nifmRequestUnregisterSocketDescriptor(&m_req, fd); }
            close(fd);
        };

        constexpr u8 QueryId0 = 0x13, QueryId1 = 0x37;
        u8 q[300];
        size_t p = 0;
        /* DNS header: id, flags=RD, qdcount=1, an/ns/ar=0; then qname, qtype A, qclass IN. */
        q[p++] = QueryId0; q[p++] = QueryId1;
        q[p++] = 0x01; q[p++] = 0x00;
        q[p++] = 0x00; q[p++] = 0x01;
        q[p++] = 0; q[p++] = 0; q[p++] = 0; q[p++] = 0; q[p++] = 0; q[p++] = 0;
        const char *s = host;
        while (*s != '\0') {
            const char *dot = std::strchr(s, '.');
            const size_t len = dot ? static_cast<size_t>(dot - s) : std::strlen(s);
            if (len == 0 || len > 63 || p + len + 6 >= sizeof(q)) {
                cleanup();
                return 0;
            }
            q[p++] = static_cast<u8>(len);
            std::memcpy(q + p, s, len);
            p += len;
            s += len;
            if (*s == '.') { s++; }
        }
        q[p++] = 0x00;
        q[p++] = 0x00; q[p++] = 0x01;
        q[p++] = 0x00; q[p++] = 0x01;

        if (::sendto(fd, q, p, 0, reinterpret_cast<struct sockaddr *>(&srv), sizeof(srv)) < 0) {
            cleanup();
            return 0;
        }

        u8 r[512];
        const ssize_t n = ::recvfrom(fd, r, sizeof(r), 0, nullptr, nullptr);
        cleanup();
        if (n < 12) {
            return 0;
        }
        if (r[0] != QueryId0 || r[1] != QueryId1 || (r[2] & 0x80) == 0 || (r[3] & 0x0f) != 0) {
            return 0;
        }
        const int ancount = (r[6] << 8) | r[7];
        if (ancount < 1) {
            return 0;
        }

        size_t off = 12;
        while (off < static_cast<size_t>(n) && r[off] != 0) {
            if ((r[off] & 0xc0) == 0xc0) { off += 1; break; }
            off += r[off] + 1;
        }
        off += 1 + 4;

        for (int i = 0; i < ancount && off + 12 <= static_cast<size_t>(n); i++) {
            if ((r[off] & 0xc0) == 0xc0) {
                off += 2;
            } else {
                while (off < static_cast<size_t>(n) && r[off] != 0) { off += r[off] + 1; }
                off += 1;
            }
            if (off + 10 > static_cast<size_t>(n)) {
                break;
            }
            const int type  = (r[off] << 8) | r[off + 1];
            const int rdlen = (r[off + 8] << 8) | r[off + 9];
            off += 10;
            if (type == 1 && rdlen == 4 && off + 4 <= static_cast<size_t>(n)) {
                return Be32(r + off);
            }
            off += rdlen;
        }
        return 0;
    }

    Result RelayTransport::OpenSocket() {
        /* Internet route, not LocalNetworkMode. */
        Result rc = NifmSessionManager::Acquire();
        if (R_FAILED(rc)) {
            LogFormat("relay xport: nifm acquire failed %x", rc);
            return rc;
        }
        m_have_nifm_session = true;

        rc = nifmCreateRequest(&m_req, true);
        if (R_FAILED(rc)) {
            LogFormat("relay xport: nifmCreateRequest %x", rc);
            this->CloseSocket();
            return rc;
        }
        m_have_req = true;

        rc = nifmRequestSubmitAndWait(&m_req);
        if (R_FAILED(rc)) {
            LogFormat("relay xport: submit %x", rc);
            this->CloseSocket();
            return rc;
        }
        /* Submit can return before the request is Available. */
        for (int i = 0; i < 10; i++) {
            NifmRequestState st = NifmRequestState_Invalid;
            if (R_FAILED(nifmGetRequestState(&m_req, &st)) || st == NifmRequestState_Available) {
                break;
            }
            svcSleepThread(500000000L);
        }

        u32 ip = 0;
        const u32 vsrc = (10u << 24) | (13u << 16) | EnsureClientId();
        const u32 rsrc = R_SUCCEEDED(nifmGetCurrentIpAddress(&ip)) ? ntohl(ip) : 0;

        u32 server_ip = ServerIp();
        if (server_ip == 0) {
            server_ip = this->ResolveHostname(ServerHost());
        }
        if (server_ip == 0) {
            LogFormat("relay xport: no/unresolvable server address ('%s')", ServerHost());
            this->CloseSocket();
            return MAKERESULT(0xFD, 102);
        }

        const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            LogFormat("relay xport: socket %d", errno);
            this->CloseSocket();
            return MAKERESULT(0xFD, 100);
        }

        struct sockaddr_in srv = {};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(ServerPort());
        srv.sin_addr.s_addr = htonl(server_ip);

        nifmRequestRegisterSocketDescriptor(&m_req, fd);

        int conn = -1;
        for (int i = 0; i < 3; i++) {
            conn = connect(fd, (struct sockaddr *)&srv, sizeof(srv));
            if (conn == 0) {
                break;
            }
            svcSleepThread(1000000000L);
        }
        if (conn != 0) {
            LogFormat("relay xport: connect failed %d", errno);
            nifmRequestUnregisterSocketDescriptor(&m_req, fd);
            close(fd);
            this->CloseSocket();
            return MAKERESULT(0xFD, 101);
        }

        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        m_ping_misses = 0;
        m_ping_supported = false;
        for (auto &f : m_frags) {
            f.used = false;
        }
        {
            std::scoped_lock lk(m_mutex);
            m_fd   = fd;
            m_vsrc = vsrc;
            m_rsrc = rsrc;
        }
        /* Record what we actually connected to, so the latency readout can
           refuse to show it under a different server's name. */
        g_active_server = g_selected.load();
        R_SUCCEED();
    }

    void RelayTransport::CloseSocket() {
        int fd;
        {
            std::scoped_lock lk(m_mutex);
            fd = m_fd;
            m_fd = -1;
        }
        g_active_server = -1;
        if (fd >= 0) {
            if (m_have_req) {
                nifmRequestUnregisterSocketDescriptor(&m_req, fd);
            }
            close(fd);
        }
        if (m_have_req) {
            nifmRequestCancel(&m_req);
            nifmRequestClose(&m_req);
            m_have_req = false;
        }
        if (m_have_nifm_session) {
            NifmSessionManager::Release();
            m_have_nifm_session = false;
        }
    }

    Result RelayTransport::Open() {
        if (m_published) {
            return this->Reopen();
        }
        const Result rc = this->OpenSocket();
        if (R_FAILED(rc)) {
            return rc;
        }
        BridgePublish(this);
        m_published = true;
        this->SendKeepalive();
        tcprelay::Start();
        LogFormat("relay xport: open, %s:%u vsrc=%08x rsrc=%08x fd=%d",
                  ServerHost(), ServerPort(), m_vsrc, m_rsrc, m_fd);
        R_SUCCEED();
    }

    void RelayTransport::Close() {
        if (m_published) {
            /* Stop before unpublishing: it sends tunnel closes through the bridge. */
            tcprelay::Stop();
            BridgeUnpublish(this);
            m_published = false;
        }
        this->CloseSocket();
    }

        Result RelayTransport::Reopen() {
        if (!m_published) {
            this->CloseSocket();
            return this->Open();
        }
        this->CloseSocket();
        /* A plain socket swap was not enough. Logs showed the first
           connection answering no ping at all for 75s while inbound frames
           kept flowing; only closing the room fixed it, which is the one
           action that also drops ICommunicationService's nifm reference and
           therefore really tears the network session down. Do that here. */
        const Result rr = NifmSessionManager::ForceReinit();
        if (R_FAILED(rr)) {
            LogFormat("relay xport: nifm force reinit failed %x", rr);
        }
        const Result rc = this->OpenSocket();
        if (R_SUCCEEDED(rc)) {
            this->SendKeepalive();
            LogFormat("relay xport: reopened, fd=%d", m_fd);
        }
        return rc;
    }

    u32 RelayTransport::RealIp() const {
        std::scoped_lock lk(m_mutex);
        return m_rsrc;
    }

    int RelayTransport::SendKeepalive() {
        std::scoped_lock lk(m_mutex);
        if (m_fd < 0) {
            return -1;
        }
        const u8 ka = TypeKeepalive;
        return send(m_fd, &ka, sizeof(ka), 0);
    }

    int RelayTransport::SendPing() {
        std::scoped_lock lk(m_mutex);
        if (m_fd < 0) {
            return -1;
        }
        ++m_ping_misses;
        const s64 now_ms = os::ConvertToTimeSpan(os::GetSystemTick()).GetMilliSeconds();
        /* Arm a fresh measurement when nothing is outstanding, OR when the
           outstanding one has waited far too long. Without that timeout a
           single dropped echo -- the server is often still wiring its side up
           when the first probe goes out -- would leave waiting set forever,
           and every later ping would only bump the miss counter. The reading
           then stayed blank until the transport happened to be rebuilt. */
        const int was_waiting = g_latency.waiting.load();
        const s64 since = now_ms - g_latency.pending_ms.load();
        if (was_waiting == 0 || since > PingEchoTimeoutMs) {
            g_latency.pending_ms = now_ms;
            g_latency.waiting = 1;
            if (was_waiting != 0) {
                LogFormat("relay: ping echo timed out after %lldms, re-arming", since);
            }
        }
        LogFormat("relay: ping tx fd=%d armed=%d waiting=%d since=%lldms misses=%u",
                  m_fd, was_waiting == 0, g_latency.waiting.load(), since,
                  m_ping_misses.load());
        const u8 p[4] = { TypePing, 'l', 'd', 'n' };
        const int sent = send(m_fd, p, sizeof(p), 0);
        if (sent != static_cast<int>(sizeof(p))) {
            LogFormat("relay: ping send failed rc=%d errno=%d", sent, errno);
        }
        return sent;
    }

    u32 RelayGetLatencyMs() {
        /* Only trust the reading when the open transport is talking to the
           server the menu is showing. Selecting a different server rewrites
           the config immediately but the socket keeps talking to the old host
           until the worker reopens it, and field screenshots showed one
           server's latency displayed under every other server's name. */
        if (g_active_server.load() != g_selected.load()) {
            return 0;
        }
        return g_latency.ms.load();
    }

    u32 RelayGetVirtualAddress() {
        const u16 id = g_client_id.load();
        if (id == 0) {
            return 0;
        }
        return (10u << 24) | (13u << 16) | static_cast<u32>(id);
    }

    bool RelayTransport::PathDead() const {
        if (m_fd < 0) {
            return true;
        }
        /* Only judge on misses once this server has echoed at least once.
           Seven of the eight shipped relays now answer no ping at all, and a
           reconnect did not help -- three different virtual addresses to the
           same server all stayed silent, while the same address answered
           instantly on the one server that does echo. Reconnecting on
           "never answered" would therefore buy nothing and cost a tunnel
           rebuild on every room, so a non-echoing server is simply left
           alone and the overlay keeps showing "--". */
        return m_ping_supported.load() && m_ping_misses.load() >= PingMaxMisses;
    }

    int RelayTransport::SendWrapped(u32 src, u32 dst, u16 sport, u16 dport, u16 ip_id, const void *payload, size_t len) {
        u8 buf[1 + MaxWrappedPacket];
        const u16 udplen = static_cast<u16>(8 + len);
        const u16 total  = static_cast<u16>(20 + udplen);
        buf[0] = TypeIpv4;
        u8 *ip = buf + 1;
        ip[0] = 0x45; ip[1] = 0x00; ip[2] = total >> 8; ip[3] = total & 0xff;
        ip[4] = ip_id >> 8; ip[5] = ip_id & 0xff; ip[6] = 0x40; ip[7] = 0x00;
        ip[8] = 64; ip[9] = 17; ip[10] = 0; ip[11] = 0;
        ip[12] = (src >> 24) & 0xff; ip[13] = (src >> 16) & 0xff;
        ip[14] = (src >> 8) & 0xff;  ip[15] = src & 0xff;
        ip[16] = (dst >> 24) & 0xff; ip[17] = (dst >> 16) & 0xff;
        ip[18] = (dst >> 8) & 0xff;  ip[19] = dst & 0xff;
        const u16 cs = IpChecksum(ip, 20);
        ip[10] = cs >> 8; ip[11] = cs & 0xff;
        u8 *udp = ip + 20;
        udp[0] = sport >> 8; udp[1] = sport & 0xff;
        udp[2] = dport >> 8; udp[3] = dport & 0xff;
        udp[4] = udplen >> 8; udp[5] = udplen & 0xff;
        udp[6] = 0; udp[7] = 0;
        if (len > 0) {
            std::memcpy(udp + 8, payload, len);
        }

        if (static_cast<size_t>(total) + 1 > SingleFrameMax) {
            return this->SendFragmented(src, dst, ip, total);
        }
        return send(m_fd, buf, 1 + total, 0);
    }

    int RelayTransport::SendFragmented(u32 src, u32 dst, const u8 *packet, size_t total) {
        const u8 parts = static_cast<u8>((total + FragPmtu - 1) / FragPmtu);
        const u16 id = m_frag_send_id++;
        int sent = 0;
        for (u8 part = 0; part < parts; part++) {
            const size_t off   = static_cast<size_t>(FragPmtu) * part;
            const size_t remaining = total - off;
            const size_t chunk = remaining < static_cast<size_t>(FragPmtu) ? remaining : static_cast<size_t>(FragPmtu);

            u8 f[1 + 16 + FragPmtu];
            f[0] = TypeIpv4Frag;
            u8 *h = f + 1;
            h[0] = (src >> 24) & 0xff; h[1] = (src >> 16) & 0xff;
            h[2] = (src >> 8) & 0xff;  h[3] = src & 0xff;
            h[4] = (dst >> 24) & 0xff; h[5] = (dst >> 16) & 0xff;
            h[6] = (dst >> 8) & 0xff;  h[7] = dst & 0xff;
            h[8] = id >> 8; h[9] = id & 0xff;
            h[10] = part;
            h[11] = parts;
            h[12] = static_cast<u8>(chunk >> 8); h[13] = static_cast<u8>(chunk & 0xff);
            h[14] = FragPmtu >> 8; h[15] = FragPmtu & 0xff;
            std::memcpy(h + 16, packet + off, chunk);

            const int n = send(m_fd, f, 1 + 16 + chunk, 0);
            if (n < 0) {
                return -1;
            }
            sent += n;
        }
        return sent;
    }

    int RelayTransport::SendBroadcast(const void *lan_packet, size_t size) {
        std::scoped_lock lk(m_mutex);
        if (m_fd < 0 || size > MaxWrapPayload) {
            return -1;
        }
        return this->SendWrapped(m_vsrc, 0x0A0DFFFFu, 11452, 11452, IpIdControl, lan_packet, size);
    }

    int RelayTransport::SendGameBroadcast(const void *payload, size_t len, u16 dport) {
        std::scoped_lock lk(m_mutex);
        return this->SendGameUnicastLocked(payload, len, dport, 0xFFFFFFFFu);
    }

    int RelayTransport::SendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip) {
        std::scoped_lock lk(m_mutex);
        return this->SendGameUnicastLocked(payload, len, dport, dst_ip);
    }

    int RelayTransport::SendGameUnicastLocked(const void *payload, size_t len, u16 dport, u32 dst_ip) {
        if (m_fd < 0 || m_rsrc == 0 || len > MaxWrapPayload) {
            return -1;
        }
        /* Route by virtual address (LAN IPs collide across NATs); real IPs ride
           in the shim. sport = dport: the true sport is not visible here. */
        const bool bcast = (dst_ip == 0xFFFFFFFFu);
        const u32 vdst = bcast ? 0xFFFFFFFFu : this->LookupVsrc(dst_ip);
        if (vdst != 0) {
            u8 shimmed[GameShimLen + MaxWrapPayload];
            shimmed[0] = (m_rsrc >> 24) & 0xff; shimmed[1] = (m_rsrc >> 16) & 0xff;
            shimmed[2] = (m_rsrc >> 8) & 0xff;  shimmed[3] = m_rsrc & 0xff;
            shimmed[4] = (dst_ip >> 24) & 0xff; shimmed[5] = (dst_ip >> 16) & 0xff;
            shimmed[6] = (dst_ip >> 8) & 0xff;  shimmed[7] = dst_ip & 0xff;
            if (len > 0) {
                std::memcpy(shimmed + GameShimLen, payload, len);
            }
            return this->SendWrapped(m_vsrc, vdst, dport, dport, IpIdGameV2, shimmed, GameShimLen + len);
        }
        return this->SendWrapped(m_rsrc, dst_ip, dport, dport, IpIdGame, payload, len);
    }

    void RelayTransport::LearnPeer(u32 real_ip, u32 vsrc) {
        u32 self_real, self_vsrc;
        {
            std::scoped_lock lk(m_mutex);
            self_real = m_rsrc;
            self_vsrc = m_vsrc;
        }
        /* Only 10.13/16 sources are relay clients. */
        if (real_ip == 0 || real_ip == self_real || vsrc == 0 || vsrc == self_vsrc ||
            (vsrc & 0xFFFF0000u) != 0x0A0D0000u) {
            return;
        }
        std::scoped_lock lk(m_peer_mutex);
        for (auto &p : m_peers) {
            if (p.real == real_ip) {
                if (p.vsrc != vsrc) {
                    LogFormat("relay: peer %08x vsrc %08x -> %08x", real_ip, p.vsrc, vsrc);
                    p.vsrc = vsrc;
                }
                return;
            }
        }
        LogFormat("relay: peer %08x at vsrc %08x", real_ip, vsrc);
        m_peers[m_peer_next] = { real_ip, vsrc };
        m_peer_next = (m_peer_next + 1) % PeerMapMax;
    }

    u32 RelayTransport::LookupVsrc(u32 real_ip) const {
        std::scoped_lock lk(m_peer_mutex);
        for (const auto &p : m_peers) {
            if (p.real == real_ip) {
                return p.vsrc;
            }
        }
        return 0;
    }

    int RelayTransport::SendScope(u32 token) {
        std::scoped_lock lk(m_mutex);
        if (m_fd < 0) {
            return -1;
        }
        const u8 p[5] = { TypeScope,
            static_cast<u8>((token >> 24) & 0xff), static_cast<u8>((token >> 16) & 0xff),
            static_cast<u8>((token >> 8) & 0xff),  static_cast<u8>(token & 0xff) };
        return send(m_fd, p, sizeof(p), 0);
    }

    bool RelayTransport::UnwrapGameShim(const u8 *ip, const u8 **payload, size_t *len, u32 *src) const {
        *src = Be32(ip + 12);
        const u16 ip_id = (static_cast<u16>(ip[4]) << 8) | ip[5];
        if (ip_id != IpIdGameV2) {
            return true;
        }
        if (*len < GameShimLen || *src == m_vsrc) {
            return false;
        }
        *src = Be32(*payload);
        *payload += GameShimLen;
        *len -= GameShimLen;
        return true;
    }

    void RelayTransport::InjectGameFrame(const u8 *ip, size_t iplen) {
        if (m_rsrc == 0) {
            return;
        }
        const size_t ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20 || ihl + 8 > iplen) {
            return;
        }
        const u8 *udp = ip + ihl;
        const u16 sport = (udp[0] << 8) | udp[1];
        const u16 dport = (udp[2] << 8) | udp[3];
        const u8 *payload = udp + 8;
        size_t plen = (ip + iplen) - payload;
        u32 src = 0;

        static std::atomic<u32> s_inject{0};
        const u32 in = s_inject.fetch_add(1, std::memory_order_relaxed) + 1;
        const bool diag = (in <= 8 || (in % 256) == 0);

        if (!this->UnwrapGameShim(ip, &payload, &plen, &src) || plen > MaxWrapPayload) {
            return;
        }
        if (src == m_rsrc) {
            if (diag) { LogFormat("diag inject #%u DROP own-echo src %08x", in, src); }
            return;
        }
        if (!IsSessionPeer(src)) {
            static std::atomic<u32> s_notpeer{0};
            const u32 nd = s_notpeer.fetch_add(1, std::memory_order_relaxed) + 1;
            if (diag || (nd & (nd - 1)) == 0) {
                LogFormat("diag inject #%u DROP not-peer src %08x dport %u (total %u)", in, src, dport, nd);
            }
            return;
        }

        if (diag) {
            const bool v2 = ((static_cast<u16>(ip[4]) << 8) | ip[5]) == IpIdGameV2;
            LogFormat("diag inject #%u PUSH src %08x sport %u dport %u len %zu%s",
                in, src, sport, dport, plen, v2 ? " (v2)" : "");
        }
        /* The local stack cannot deliver a foreign source IP; bsd:u RecvFrom
           serves it from GameRx instead. */
        GameRx::Push(src, sport, dport, payload, plen);
    }

    int RelayTransport::RecvBroadcast(void *out, size_t max_size, u32 *out_src_ip) {
        if (m_fd < 0) {
            return -1;
        }
        u8 buf[2048];
        const ssize_t n = recv(m_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            return (n == 0) ? 0 : -1;
        }
        const u8 type = buf[0] & 0x7f;
        if (type == TypePing) {
            /* Only an actual echo clears the miss counter. Clearing it on any
               inbound frame let relayed Scan broadcasts reset the streak, so
               the "never answered" detection below rarely tripped. */
            m_ping_supported = true;
            m_ping_misses = 0;
            /* The server echoes our PING verbatim: compute the round trip. */
            const int was_waiting = g_latency.waiting.exchange(0);
            const s64 rtt = os::ConvertToTimeSpan(os::GetSystemTick()).GetMilliSeconds()
                            - g_latency.pending_ms.load();
            if (was_waiting != 0 && rtt >= 0 && rtt < 10000) {
                g_latency.ms = static_cast<u32>(rtt);
                LogFormat("relay: ping echo rtt=%lldms -> %ums", rtt, g_latency.ms.load());
            } else {
                LogFormat("relay: ping echo dropped (waiting=%d rtt=%lldms)", was_waiting, rtt);
            }
            return 0;
        }
        if (type == TypeIpv4Frag) {
            size_t iplen = 0;
            const u8 *ip = this->ReassembleFrag(buf + 1, static_cast<size_t>(n) - 1, &iplen);
            if (ip == nullptr) {
                return 0;
            }
            return this->ProcessIpv4(ip, iplen, out, max_size, out_src_ip);
        }
        if (type != TypeIpv4) {
            return 0;
        }
        return this->ProcessIpv4(buf + 1, static_cast<size_t>(n) - 1, out, max_size, out_src_ip);
    }

    const u8 *RelayTransport::ReassembleFrag(const u8 *p, size_t n, size_t *out_len) {
        /* lan-play IPV4_FRAG header (16B, BE): src dst id part total_part len
           pmtu; the chunk sits at pmtu*part. */
        constexpr size_t HeaderLen = 16;
        if (n < HeaderLen) {
            return nullptr;
        }
        const u32 src   = Be32(p);
        const u16 id    = (p[8] << 8) | p[9];
        const u8  part  = p[10];
        const u8  total = p[11];
        const u16 len   = (p[12] << 8) | p[13];
        const u16 pmtu  = (p[14] << 8) | p[15];
        const size_t off = static_cast<size_t>(pmtu) * part;
        /* Untrusted header: bound every field before use as an offset. */
        if (total == 0 || total > FragMaxParts || part >= total ||
            len > n - HeaderLen || off + len > sizeof(m_frags[0].buffer)) {
            return nullptr;
        }

        FragSlot *slot = nullptr;
        for (auto &f : m_frags) {
            if (f.used && f.id == id && f.src == src) {
                slot = &f;
                break;
            }
        }
        if (slot == nullptr) {
            for (auto &f : m_frags) {
                if (!f.used) {
                    slot = &f;
                    break;
                }
            }
            if (slot == nullptr) {
                slot = &m_frags[m_frag_evict++ % FragSlots];
            }
            slot->used = true;
            slot->id = id;
            slot->src = src;
            slot->mask = 0;
            slot->total_len = 0;
        }

        slot->mask |= 1u << part;
        std::memcpy(slot->buffer + off, p + HeaderLen, len);
        if (part == total - 1) {
            slot->total_len = static_cast<u16>(off + len);
        }
        if (slot->mask == static_cast<u8>(~(0xFFu << total))) {
            slot->used = false;
            *out_len = slot->total_len;
            return slot->buffer;
        }
        return nullptr;
    }

    int RelayTransport::ProcessIpv4(const u8 *ip, size_t iplen, void *out, size_t max_size, u32 *out_src_ip) {
        if (iplen < 20) {
            return 0;
        }
        const size_t ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20 || ihl > iplen || ip[9] != 17) {
            return 0;
        }
        const u8 *udp = ip + ihl;
        if (ip + iplen < udp + 8) {
            return 0;
        }
        const u16 dport = (udp[2] << 8) | udp[3];
        if (dport == tcprelay::TcpTunnelPort) {
            const u8 *tp = udp + 8;
            size_t tlen = static_cast<size_t>((ip + iplen) - tp);
            u32 src = 0;
            if (this->UnwrapGameShim(ip, &tp, &tlen, &src) && tlen > 0 && src != m_rsrc && IsSessionPeer(src)) {
                tcprelay::OnTunnelFrame(src, tp, tlen);
            }
            return 0;
        }
        if (dport != 11452) { /* LANDiscovery::DefaultPort */
            this->InjectGameFrame(ip, iplen);
            return 0;
        }
        const u8 *payload = udp + 8;
        const size_t plen = static_cast<size_t>((ip + iplen) - payload);
        if (plen == 0 || plen > max_size) {
            return 0;
        }
        if (out_src_ip) {
            *out_src_ip = Be32(ip + 12);
        }
        std::memcpy(out, payload, plen);
        return static_cast<int>(plen);
    }

}
