#include "ldn.h"
#include <string.h>

Result ldnMitmGetConfig(LdnMitmConfigService *out) {
    Handle handle;
    Result rc = svcConnectToNamedPort(&handle, "ldnmitm");
    if (R_SUCCEEDED(rc)) {
        serviceCreate(&out->s, handle);
    }
    return rc;
}

Result ldnMitmGetConfigFromService(Service* s, LdnMitmConfigService *out) {
    return serviceDispatch(s, 65000,
        .out_num_objects = 1,
        .out_objects = &out->s
    );
}

Result ldnMitmGetLogging(LdnMitmConfigService *s, u32 *enabled) {
    return serviceDispatchOut(&s->s, 65002, *enabled);
}

Result ldnMitmSetLogging(LdnMitmConfigService *s, u32 enabled) {
    return serviceDispatchIn(&s->s, 65003, enabled);
}

Result ldnMitmGetEnabled(LdnMitmConfigService *s, u32 *enabled) {
    return serviceDispatchOut(&s->s, 65004, *enabled);
}

Result ldnMitmSetEnabled(LdnMitmConfigService *s, u32 enabled) {
    return serviceDispatchIn(&s->s, 65005, enabled);
}

Result ldnMitmGetBroadcastRelay(LdnMitmConfigService *s, u32 *enabled) {
    return serviceDispatchOut(&s->s, 65006, *enabled);
}

Result ldnMitmSetBroadcastRelay(LdnMitmConfigService *s, u32 enabled) {
    return serviceDispatchIn(&s->s, 65007, enabled);
}

Result ldnMitmGetInternetRelay(LdnMitmConfigService *s, u32 *enabled) {
    return serviceDispatchOut(&s->s, 65008, *enabled);
}

Result ldnMitmSetInternetRelay(LdnMitmConfigService *s, u32 enabled) {
    return serviceDispatchIn(&s->s, 65009, enabled);
}

Result ldnMitmGetRelayServerCount(LdnMitmConfigService *s, u32 *count) {
    return serviceDispatchOut(&s->s, 65010, *count);
}

Result ldnMitmGetRelayServerName(LdnMitmConfigService *s, u32 index, char *name) {
    char name_s[32];
    Result rc = serviceDispatchInOut(&s->s, 65011, index, name_s);
    if (R_SUCCEEDED(rc)) {
        memcpy(name, name_s, sizeof(name_s));
        name[31] = '\0';
    }
    return rc;
}

Result ldnMitmGetSelectedRelayServer(LdnMitmConfigService *s, u32 *index) {
    return serviceDispatchOut(&s->s, 65012, *index);
}

Result ldnMitmSetSelectedRelayServer(LdnMitmConfigService *s, u32 index) {
    return serviceDispatchIn(&s->s, 65013, index);
}

Result ldnMitmGetRelayLatency(LdnMitmConfigService *s, u32 *ms) {
    return serviceDispatchOut(&s->s, 65014, *ms);
}

Result ldnMitmGetRelayVirtualAddress(LdnMitmConfigService *s, u32 *addr) {
    return serviceDispatchOut(&s->s, 65015, *addr);
}

Result ldnMitmGetRelayIdSource(LdnMitmConfigService *s, u32 *source) {
    return serviceDispatchOut(&s->s, 65016, *source);
}

Result ldnMitmGetRelayLocalIp(LdnMitmConfigService *s, u32 *addr) {
    return serviceDispatchOut(&s->s, 65017, *addr);
}

/* --- runtime server management ----------------------------------------- */

Result ldnMitmGetRelayServerInfo(LdnMitmConfigService *s, u32 index, LdnRelayServerInfo *info) {
    LdnRelayServerInfo out;
    Result rc = serviceDispatchInOut(&s->s, 65018, index, out);
    if (R_SUCCEEDED(rc)) {
        out.name[sizeof(out.name) - 1] = '\0';
        out.host[sizeof(out.host) - 1] = '\0';
        *info = out;
    }
    return rc;
}

Result ldnMitmAddRelayServer(LdnMitmConfigService *s, const LdnRelayServerInfo *info) {
    /* hipc needs the payload as raw bytes; copying into a local mutable
       struct also lets us guarantee NUL termination. */
    LdnRelayServerInfo in = *info;
    in.name[sizeof(in.name) - 1] = '\0';
    in.host[sizeof(in.host) - 1] = '\0';
    return serviceDispatchIn(&s->s, 65019, in);
}

Result ldnMitmDeleteRelayServer(LdnMitmConfigService *s, u32 index) {
    return serviceDispatchIn(&s->s, 65020, index);
}

Result ldnMitmRestoreDefaultRelayServers(LdnMitmConfigService *s) {
    return serviceDispatch(&s->s, 65021);
}

Result ldnMitmGetBuiltinRelayServerCount(LdnMitmConfigService *s, u32 *count) {
    return serviceDispatchOut(&s->s, 65022, *count);
}

Result ldnMitmGetBuiltinRelayServerInfo(LdnMitmConfigService *s, u32 index, LdnRelayServerInfo *info) {
    LdnRelayServerInfo out;
    Result rc = serviceDispatchInOut(&s->s, 65023, index, out);
    if (R_SUCCEEDED(rc)) {
        out.name[sizeof(out.name) - 1] = '\0';
        out.host[sizeof(out.host) - 1] = '\0';
        *info = out;
    }
    return rc;
}

Result ldnMitmGetVersion(LdnMitmConfigService *s, char *version) {
    char version_s[32];
    Result rc = serviceDispatchOut(&s->s, 65001, version_s);
    if (R_SUCCEEDED(rc)) {
        strcpy(version, version_s);
    }
    return rc;
}

Result ldnMitmSaveLogToFile(LdnMitmConfigService *s) {
    return serviceDispatch(&s->s, 65000);
}