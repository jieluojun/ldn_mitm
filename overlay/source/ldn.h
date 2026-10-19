#pragma once
#include <switch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    Service s;
} LdnMitmConfigService;

/* Must match relay_client.hpp's MaxServers. */
#define LDN_MAX_SERVERS 32

Result ldnMitmSaveLogToFile(LdnMitmConfigService *s);
Result ldnMitmGetVersion(LdnMitmConfigService *s, char *version);
Result ldnMitmGetLogging(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetLogging(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetEnabled(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetEnabled(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetBroadcastRelay(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetBroadcastRelay(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetInternetRelay(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetInternetRelay(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetRelayServerCount(LdnMitmConfigService *s, u32 *count);
Result ldnMitmGetRelayServerName(LdnMitmConfigService *s, u32 index, char *name);
Result ldnMitmGetSelectedRelayServer(LdnMitmConfigService *s, u32 *index);
Result ldnMitmSetSelectedRelayServer(LdnMitmConfigService *s, u32 index);
/* Last relay PING round-trip time in ms; 0 = not measured yet. */
Result ldnMitmGetRelayLatency(LdnMitmConfigService *s, u32 *ms);
/* Our virtual address, host order (0x0A0Dxxxx = 10.13.x.x); 0 if unassigned. */
Result ldnMitmGetRelayVirtualAddress(LdnMitmConfigService *s, u32 *addr);
/* How the id was assigned: 0 unknown, 1 hardware-derived, 2 random. */
Result ldnMitmGetRelayIdSource(LdnMitmConfigService *s, u32 *source);
/* This console's LAN address, host order; 0 if unavailable. */
Result ldnMitmGetRelayLocalIp(LdnMitmConfigService *s, u32 *addr);
/* Runtime server management: add one entry, drop one, or restore factory
   defaults. Each call rewrites relay.cfg. */
typedef struct {
    char name[32];
    char host[64];
    u16  port;
    u16  _pad;
} LdnRelayServerInfo;
Result ldnMitmGetRelayServerInfo(LdnMitmConfigService *s, u32 index, LdnRelayServerInfo *info);
Result ldnMitmAddRelayServer(LdnMitmConfigService *s, const LdnRelayServerInfo *info);
Result ldnMitmDeleteRelayServer(LdnMitmConfigService *s, u32 index);
Result ldnMitmRestoreDefaultRelayServers(LdnMitmConfigService *s);
Result ldnMitmGetBuiltinRelayServerCount(LdnMitmConfigService *s, u32 *count);
Result ldnMitmGetBuiltinRelayServerInfo(LdnMitmConfigService *s, u32 index, LdnRelayServerInfo *info);
Result ldnMitmGetConfig(LdnMitmConfigService *out);
Result ldnMitmGetConfigFromService(Service* s, LdnMitmConfigService *out);

#ifdef __cplusplus
}
#endif
