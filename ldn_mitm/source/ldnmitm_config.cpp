#include <cstring>
#include "ldnmitm_config.hpp"
#include "relay_client.hpp"
#include "debug.hpp"

namespace ams::mitm::ldn {
    std::atomic_bool LdnConfig::LdnEnabled = true;
    std::atomic_bool LdnConfig::BroadcastRelay = true;

    Result LdnConfig::GetVersion(sf::Out<LdnMitmVersion> version) {
        std::strcpy(version.GetPointer()->raw, GITDESCVER);
        
        R_SUCCEED();
    }
    Result LdnConfig::GetLogging(sf::Out<u32> enabled) {
        return ::GetLogging(enabled.GetPointer());
    }
    Result LdnConfig::SetLogging(u32 enabled) {
        return ::SetLogging(enabled);
    }
    Result LdnConfig::GetEnabled(sf::Out<u32> enabled) {
        enabled.SetValue(LdnEnabled);
        
        R_SUCCEED();
    }
    Result LdnConfig::SetEnabled(u32 enabled) {
        LdnEnabled = enabled;

        R_SUCCEED();
    }
    Result LdnConfig::GetBroadcastRelay(sf::Out<u32> enabled) {
        enabled.SetValue(BroadcastRelay);

        R_SUCCEED();
    }
    Result LdnConfig::SetBroadcastRelay(u32 enabled) {
        BroadcastRelay = enabled;
        relay::PersistSettings();

        R_SUCCEED();
    }

    Result LdnConfig::GetInternetRelay(sf::Out<u32> enabled) {
        enabled.SetValue(relay::GetRelayEnabled() ? 1 : 0);
        R_SUCCEED();
    }
    Result LdnConfig::SetInternetRelay(u32 enabled) {
        relay::SetRelayEnabled(enabled != 0);
        R_SUCCEED();
    }
    Result LdnConfig::GetRelayServerCount(sf::Out<u32> count) {
        count.SetValue(static_cast<u32>(relay::ServerCount()));
        R_SUCCEED();
    }
    Result LdnConfig::GetRelayServerName(u32 index, sf::Out<RelayServerName> name) {
        RelayServerName out = {};
        std::strncpy(out.name, relay::ServerName(static_cast<int>(index)), sizeof(out.name) - 1);
        name.SetValue(out);
        R_SUCCEED();
    }
    Result LdnConfig::GetSelectedRelayServer(sf::Out<u32> index) {
        index.SetValue(static_cast<u32>(relay::SelectedServer()));
        R_SUCCEED();
    }
    Result LdnConfig::SetSelectedRelayServer(u32 index) {
        relay::SelectServer(static_cast<int>(index));
        R_SUCCEED();
    }
    Result LdnConfig::GetRelayLatency(sf::Out<u32> ms) {
        ms.SetValue(relay::RelayGetLatencyMs());
        R_SUCCEED();
    }
    Result LdnConfig::GetRelayVirtualAddress(sf::Out<u32> addr) {
        addr.SetValue(relay::RelayGetVirtualAddress());
        R_SUCCEED();
    }
    Result LdnConfig::GetRelayIdSource(sf::Out<u32> source) {
        source.SetValue(static_cast<u32>(relay::RelayGetIdSource()));
        R_SUCCEED();
    }
    Result LdnConfig::GetRelayLocalIp(sf::Out<u32> addr) {
        addr.SetValue(relay::RelayGetLocalIp());
        R_SUCCEED();
    }

    /* --- runtime server management ------------------------------------- */

    Result LdnConfig::GetRelayServerInfo(u32 index, sf::Out<RelayServerInfo> info) {
        RelayServerInfo out = {};
        std::strncpy(out.name, relay::ServerName(static_cast<int>(index)), sizeof(out.name) - 1);
        std::strncpy(out.host, relay::ServerHostAt(static_cast<int>(index)), sizeof(out.host) - 1);
        out.port = relay::ServerPortAt(static_cast<int>(index));
        info.SetValue(out);
        R_SUCCEED();
    }
    Result LdnConfig::AddRelayServer(RelayServerInfo info) {
        /* Copy out of the SF struct first: the strings are fixed-size and may
           not be NUL-terminated if a caller sent all 32/64 bytes. */
        char name[32] = {};
        char host[64] = {};
        std::memcpy(name, info.name, sizeof(name) - 1);
        std::memcpy(host, info.host, sizeof(host) - 1);
        if (!relay::AddServer(name, host, info.port)) {
            LogFormat("relay: add server rejected (%s:%u)", host, static_cast<unsigned>(info.port));
            return MAKERESULT(Module_Libnx, LibnxError_BadInput);
        }
        R_SUCCEED();
    }
    Result LdnConfig::DeleteRelayServer(u32 index) {
        if (!relay::DeleteServer(static_cast<int>(index))) {
            return MAKERESULT(Module_Libnx, LibnxError_BadInput);
        }
        R_SUCCEED();
    }
    Result LdnConfig::RestoreDefaultRelayServers() {
        relay::RestoreDefaultServers();
        R_SUCCEED();
    }
    Result LdnConfig::GetBuiltinRelayServerCount(sf::Out<u32> count) {
        count.SetValue(static_cast<u32>(relay::BuiltinServerCount()));
        R_SUCCEED();
    }
    Result LdnConfig::GetBuiltinRelayServerInfo(u32 index, sf::Out<RelayServerInfo> info) {
        RelayServerInfo out = {};
        std::strncpy(out.name, relay::BuiltinServerName(static_cast<int>(index)), sizeof(out.name) - 1);
        std::strncpy(out.host, relay::BuiltinServerHost(static_cast<int>(index)), sizeof(out.host) - 1);
        out.port = relay::BuiltinServerPort(static_cast<int>(index));
        info.SetValue(out);
        R_SUCCEED();
    }
}
