#pragma once
#include <stratosphere.hpp>

namespace ams::mitm::ldn {

    struct LdnMitmVersion {
        char raw[32];
    };

    struct RelayServerName {
        char name[32];
    };

    /* Full relay entry, used by the overlay's server management page.
       Fixed-size on purpose: SF cannot carry variable-length strings
       without an InBuffer, and 96 bytes is small enough to send as-is. */
    struct RelayServerInfo {
        char name[32];
        char host[64];
        u16  port;
        u16  _pad;
    };

}

#define AMS_LDN_CONFIG(C, H)                                                                									\
    AMS_SF_METHOD_INFO(C, H, 65001, Result, GetVersion, 	(ams::sf::Out<ams::mitm::ldn::LdnMitmVersion> version), (version))  \
    AMS_SF_METHOD_INFO(C, H, 65002, Result, GetLogging, 	(ams::sf::Out<u32> enabled), 							(enabled))	\
    AMS_SF_METHOD_INFO(C, H, 65003, Result, SetLogging, 	(u32 enabled), 											(enabled))	\
    AMS_SF_METHOD_INFO(C, H, 65004, Result, GetEnabled, 	(ams::sf::Out<u32> enabled), 							(enabled))	\
    AMS_SF_METHOD_INFO(C, H, 65005, Result, SetEnabled, 	(u32 enabled), 											(enabled))	\
    AMS_SF_METHOD_INFO(C, H, 65006, Result, GetBroadcastRelay, 	(ams::sf::Out<u32> enabled), 						(enabled))	\
    AMS_SF_METHOD_INFO(C, H, 65007, Result, SetBroadcastRelay, 	(u32 enabled), 										(enabled))	\
    AMS_SF_METHOD_INFO(C, H, 65008, Result, GetInternetRelay, 	(ams::sf::Out<u32> enabled), 						(enabled))	\
    AMS_SF_METHOD_INFO(C, H, 65009, Result, SetInternetRelay, 	(u32 enabled), 										(enabled))	\
    AMS_SF_METHOD_INFO(C, H, 65010, Result, GetRelayServerCount, 	(ams::sf::Out<u32> count), 						(count))	\
    AMS_SF_METHOD_INFO(C, H, 65011, Result, GetRelayServerName, 	(u32 index, ams::sf::Out<ams::mitm::ldn::RelayServerName> name), (index, name))	\
    AMS_SF_METHOD_INFO(C, H, 65012, Result, GetSelectedRelayServer, 	(ams::sf::Out<u32> index), 					(index))	\
    AMS_SF_METHOD_INFO(C, H, 65013, Result, SetSelectedRelayServer, 	(u32 index), 								(index))	\
    AMS_SF_METHOD_INFO(C, H, 65014, Result, GetRelayLatency, 	(ams::sf::Out<u32> ms), 						(ms))	\
    AMS_SF_METHOD_INFO(C, H, 65015, Result, GetRelayVirtualAddress, 	(ams::sf::Out<u32> addr), 					(addr))	\
    AMS_SF_METHOD_INFO(C, H, 65016, Result, GetRelayIdSource, 	(ams::sf::Out<u32> source), 					(source))	\
    AMS_SF_METHOD_INFO(C, H, 65017, Result, GetRelayLocalIp, 	(ams::sf::Out<u32> addr), 						(addr))	\
    AMS_SF_METHOD_INFO(C, H, 65018, Result, GetRelayServerInfo, (u32 index, ams::sf::Out<ams::mitm::ldn::RelayServerInfo> info), (index, info))	\
    AMS_SF_METHOD_INFO(C, H, 65019, Result, AddRelayServer, 	(ams::mitm::ldn::RelayServerInfo info), 			(info))	\
    AMS_SF_METHOD_INFO(C, H, 65020, Result, DeleteRelayServer, 	(u32 index), 									(index))	\
    AMS_SF_METHOD_INFO(C, H, 65021, Result, RestoreDefaultRelayServers, (), 										())	\
    AMS_SF_METHOD_INFO(C, H, 65022, Result, GetBuiltinRelayServerCount, (ams::sf::Out<u32> count), 					(count))	\
    AMS_SF_METHOD_INFO(C, H, 65023, Result, GetBuiltinRelayServerInfo, (u32 index, ams::sf::Out<ams::mitm::ldn::RelayServerInfo> info), (index, info))

    AMS_SF_DEFINE_INTERFACE(ams::mitm::ldn, ILdnConfig, AMS_LDN_CONFIG, 0x14c8af2c)
