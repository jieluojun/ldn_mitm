/* 联机监视器实现:订阅下载 + 服务器查询 + UDP 房间扫描 + 后台刷新。
 *
 * 数据口径与 LanPlayMonitor 一致:
 *   graphql 服务器  POST http://host:port/  {"query": PublicRoomSnapshot}
 *   rest 服务器     GET  http://host:port/info
 *   1.0(rest)服务器 /info 不给房间列表,用 lan-play 中继协议的
 *   LDN 主动扫描补房间(对应 LanPlayMonitor 的 active-udp-scan)。
 */
#include "monitor.hpp"
#include "monitor_title_resolver.hpp"
#include "monitor_player_filter.hpp"
#include "monitor_target_generation.hpp"

#include <switch.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <curl/curl.h>

/* ------------------------------------------------------------------ */
/* 常量                                                                */
/* ------------------------------------------------------------------ */

static const char *kSubChinesePath = "jieluojun/LanPlayMonitor/refs/heads/main/chinese_db.json";

/* 下载通道:HTTPS 加速镜像优先(https://v6.gh-proxy.org/ 直接加在 GitHub
 * 链接前面;GitHub 已全站强制 HTTPS,纯 HTTP 通道几乎都被 301,仅作兜底)。
 * 服务器列表不再订阅 servers.json —— 只读 relay.cfg。 */
static const char *kUrlPrefixes[] = {
    "https://v6.gh-proxy.org/https://raw.githubusercontent.com/",
    "http://raw.githubusercontent.com/",
    "http://gh-proxy.com/https://raw.githubusercontent.com/",
    "http://ghfast.top/https://raw.githubusercontent.com/",
};

static const char *kGraphqlQuery =
    "query PublicRoomSnapshot { serverInfo { online idle } room {"
    " sessionId contentId advertiseData hostPlayerName nodeCount nodeCountMax"
    " nodes { playerName isConnected } } }";

/* Query variants keep older custom GraphQL schemas working while preferring
 * both per-room title data and NodeInfo.isConnected. The latter is essential:
 * servers may retain names in disconnected node slots. */
static const char *kGraphqlQueryNoAdvert =
    "query PublicRoomSnapshot { serverInfo { online idle } room {"
    " sessionId contentId hostPlayerName nodeCount nodeCountMax"
    " nodes { playerName isConnected } } }";
static const char *kGraphqlQueryNoConnection =
    "query PublicRoomSnapshot { serverInfo { online idle } room {"
    " sessionId contentId advertiseData hostPlayerName nodeCount nodeCountMax"
    " nodes { playerName } } }";
static const char *kGraphqlQueryOldest =
    "query PublicRoomSnapshot { serverInfo { online idle } room {"
    " sessionId contentId hostPlayerName nodeCount nodeCountMax"
    " nodes { playerName } } }";

static const char *kSaveDir         = "sdmc:/config/ldn_mitm";
static const char *kSaveChinesePath = "sdmc:/config/ldn_mitm/chinese_db.json";
static const char *kRelayCfgPath    = "sdmc:/config/ldn_mitm/relay.cfg";
static const char *kLogPath         = "sdmc:/config/ldn_mitm/monitor.log";

/* 诊断日志:记录各阶段,便于定位 ovlloader 堆不足时的爆点。
 * 每次 MonitorInit 截断重写。 */
static bool g_sdMounted = false;
static void EnsureSd() {
    /* tesla 覆盖了 __appInit,libnx 默认实现里的 fsdevMountSdmc() 不会执行,
     * 必须自行挂载,否则 sdmc: 的 fopen 全部失败(曾导致 fclose(NULL) 崩溃)。 */
    if (!g_sdMounted) {
        fsdevMountSdmc();
        g_sdMounted = true;
    }
}

/* 日志改成「先缓冲、后落盘」:
 * 打开插件的首帧之前不能碰 SD 卡(fsdevMountSdmc + fopen 在冷机/大卡上
 * 是秒级阻塞,这正是「点开插件要过一会才弹出来」的主要来源)。所以启动
 * 路径上只把日志攒进内存缓冲,由后台线程在 UI 出来后一次性打开文件并
 * 把缓冲刷进去(MonitorOpenLog)。 */
static char g_logBuf[4096];
static size_t g_logLen = 0;
static bool g_logReady = false;

static void MonLog(const char *msg) {
    if (!g_logReady) {
        const size_t n = strlen(msg);
        if (g_logLen + n + 1 < sizeof(g_logBuf)) {
            memcpy(g_logBuf + g_logLen, msg, n);
            g_logLen += n;
            g_logBuf[g_logLen++] = '\n';
        }
        return;
    }
    FILE *f = fopen(kLogPath, "a");
    if (!f)
        return;
    fputs(msg, f);
    fputc('\n', f);
    fclose(f);
}

/* 后台线程(UI 已经能画之后)才做的重活:挂载 SD、建目录、截断日志、
 * 把启动阶段缓存的日志补写进去。失败也不影响插件本身。 */
static void MonitorOpenLog() {
    if (g_logReady)
        return;
    EnsureSd();
    mkdir("sdmc:/config", 0777);
    mkdir(kSaveDir, 0777);
    FILE *lf = fopen(kLogPath, "w");
    if (lf) {
        fclose(lf);
        g_logReady = true;
    }
    if (!g_logReady)
        return;
    FILE *f = fopen(kLogPath, "a");
    if (f) {
        fwrite(g_logBuf, 1, g_logLen, f);
        fclose(f);
    }
    g_logLen = 0;
}

/* bsd socket 初始化:必须在 sm 会话内拿到 bsd:u,且尽量安排在帧缓冲
 * 分配(initScreen)之前——bsd 缓冲是 tmem 堆分配,帧缓冲之后堆很紧。
 * 失败自动用缩容缓冲重试;AlreadyInitialized 视为成功。 */
static bool g_sockInited = false;
static void EnsureSockets() {
    if (g_sockInited)
        return;
    bool ownSm = R_SUCCEEDED(smInitialize());  /* 外层已开 sm 时返回错误,不影响 */
    Result rc = socketInitializeDefault();
    if (R_FAILED(rc)) {
        SocketInitConfig cfg = *socketGetDefaultInitConfig();
        cfg.tcp_tx_buf_size = 0x4000;
        cfg.tcp_rx_buf_size = 0x8000;
        cfg.tcp_tx_buf_max_size = 0x10000;
        cfg.tcp_rx_buf_max_size = 0x10000;
        cfg.udp_tx_buf_size = 0x1400;
        cfg.udp_rx_buf_size = 0x4000;
        cfg.sb_efficiency = 2;
        cfg.num_bsd_sessions = 1;
        rc = socketInitialize(&cfg);
    }
    if (R_FAILED(rc)) {
        /* 最后一试:bsd:s(bsd:u 会话被同进程先前组件占满时可能需要) */
        SocketInitConfig cfg = *socketGetDefaultInitConfig();
        cfg.tcp_tx_buf_size = 0x4000;
        cfg.tcp_rx_buf_size = 0x8000;
        cfg.tcp_tx_buf_max_size = 0x10000;
        cfg.tcp_rx_buf_max_size = 0x10000;
        cfg.udp_tx_buf_size = 0x1400;
        cfg.udp_rx_buf_size = 0x4000;
        cfg.sb_efficiency = 2;
        cfg.num_bsd_sessions = 1;
        cfg.bsd_service_type = BsdServiceType_System;
        rc = socketInitialize(&cfg);
    }
    if (ownSm)
        smExit();
    if (R_SUCCEEDED(rc) ||
        rc == MAKERESULT(Module_Libnx, LibnxError_AlreadyInitialized))
        g_sockInited = true;
    char msg[48];
    snprintf(msg, sizeof(msg), "sockets-init %s rc=%08x",
             g_sockInited ? "ok" : "FAIL", (unsigned)rc);
    MonLog(msg);
}

void MonitorInitSockets() {
    /* 只做真正必须抢在帧缓冲之前的活:bsd 的缓冲是 tmem 堆分配,帧缓冲
     * (双缓冲约 1.34MB)先占走堆就会 0x559,所以 socket 初始化必须留在
     * createUI 之前。SD 挂载、日志截断、socket 探针这些都不急,全部丢到
     * 后台线程(MonitorOpenLog / ProbeHeap),启动路径上不再碰 SD 卡。 */
    EnsureSockets();
}

/* 堆余量探针:试分配与帧缓冲同量级的块并立即释放。
 * 崩溃时日志里的 probe 结果直接告诉我们堆还剩多少余量。
 * 现在由工作线程在 UI 起来之后调用(不再占首帧时间),含义也随之变成
 * 「帧缓冲分配之后还剩多少」——对小堆崩溃仍然是最有用的那个数。 */
static void ProbeHeap() {
    static const size_t kProbes[] = { 256u * 1024, 700u * 1024, 1400u * 1024 };
    char msg[48];
    for (size_t sz : kProbes) {
        void *p = malloc(sz);
        snprintf(msg, sizeof(msg), "probe-%uK %s",
                 (unsigned)(sz / 1024), p ? "ok" : "FAIL");
        MonLog(msg);
        if (p)
            free(p);
    }
}

#ifdef __SWITCH__
/* 帧缓冲降级兜底(-Wl,--wrap=framebufferCreate):
 * libtesla 固定双缓冲(448×720 RGBA4444×2 ≈ 1.34MB),在小堆 loader 上
 * 分配失败即 ASSERT_FATAL → 0x559 直接崩。这里失败时自动改单缓冲
 * (≈672KB,少一半),代价是重绘时可能轻微撕裂,插件仍可正常使用。 */
extern "C" Result __real_framebufferCreate(Framebuffer *fb, NWindow *win,
                                           u32 width, u32 height,
                                           u32 format, u32 num_fbs);
extern "C" Result __wrap_framebufferCreate(Framebuffer *fb, NWindow *win,
                                           u32 width, u32 height,
                                           u32 format, u32 num_fbs) {
    Result rc = __real_framebufferCreate(fb, win, width, height, format, num_fbs);
    if (R_FAILED(rc) && num_fbs > 1) {
        MonLog("fb: fallback to 1 buffer");
        rc = __real_framebufferCreate(fb, win, width, height, format, 1);
    }
    if (R_SUCCEEDED(rc))
        MonLog("fb: ready");
    return rc;
}
#endif

void MonitorLog(const char *msg) {
    MonLog(msg);
}

static constexpr size_t kMaxDownload  = 3u * 1024 * 1024;  /* 订阅文件上限 */
static constexpr size_t kMaxHttpBody  = 512u * 1024;       /* 查询响应上限 */
static constexpr u32   kTitleHashSize = 16384;             /* 标题映射哈希桶(2 的幂;须 ≥ 条目数,10521 条) */
static constexpr size_t kTitleArena   = 288u * 1024;       /* 标题名字符串池(实测 10521 条约 216KB) */
static constexpr u32   kMaxScanRooms  = 24;

/* ------------------------------------------------------------------ */
/* 全局状态                                                            */
/* ------------------------------------------------------------------ */

static std::mutex g_mutex;
static MonitorSnapshot g_snap;

static std::atomic<u32>  g_reqGen{0};
/* Request epoch used to reject superseded in-flight responses. */
static MonitorTargetGeneration::Gate g_targetGen;
static std::atomic<bool> g_exit{false};
static std::atomic<bool> g_traditional{false};
/* 插件隐藏(=用户按了返回)/退出时置位:在跑的订阅下载、HTTP 查询、DNS、
 * UDP 扫描立刻放弃,worker 回去睡觉 —— 返回特斯拉菜单不再等查询跑完。 */
static std::atomic<bool> g_paused{false};
/* 辅助阶段(逐台刷新其它服务器的统计)标志:此阶段遇到新的刷新请求就放弃,
 * 不去拖慢选中服务器的查询。 */
static std::atomic<bool> g_auxPhase{false};

/* 统一的中止判据:暂停/退出 → 立刻放弃;辅助阶段遇到用户切服/刷新 → 立刻放弃。
 * 注意:普通的 3 秒周期轮询(MonitorRequestPoll,不推进 g_targetGen)不打断正在进行
 * 的其它服务器单台探测,避免非选中服务器测到一半被周期轮询腰斩导致长期测不出数据。 */
static bool IoAbort();
static std::atomic<u32> g_doneGen{0};
static std::atomic<MonitorTargetGeneration::Value> g_auxTargetGen{0};
static Thread g_thread;
static bool  g_inited = false;
static char  g_pendingName[48];      /* 切换服务器时指定;空 = 读 relay.cfg */
static bool  g_pendingSubs = false;  /* 下一次刷新是否重新拉订阅缓存 */

static bool IoAbort() {
    if (g_paused.load() || g_exit.load())
        return true;
    if (!g_targetGen.IsCurrent(g_auxTargetGen.load()))
        return true;
    return false;
}

static void AbortableSleepMs(int totalMs) {
    for (int elapsed = 0; elapsed < totalMs && !IoAbort(); elapsed += 10)
        svcSleepThread(10'000'000);
}

#define T_STR(hans, hant) (g_traditional.load() ? (hant) : (hans))

/* 服务器列表:servers.json 已彻底移除,只读 relay.cfg(见 MonitorListRelayServers)。 */

/* 标题映射(chinese_db.json 订阅):开放寻址哈希 + 字符串池 */
static u64  *g_titleKey   = nullptr;    /* 存 key+1,0 = 空槽 */
static u32  *g_titleOff   = nullptr;
static u16  *g_titleLen   = nullptr;
static char *g_titleArena = nullptr;
static u32  g_titleArenaUsed = 0;
static void EnsureTitleTables();

/* ------------------------------------------------------------------ */
/* 小工具                                                              */
/* ------------------------------------------------------------------ */

static bool StrIsSpace(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static const char *JsWs(const char *p) {
    while (p && *p && StrIsSpace(*p))
        p++;
    return p;
}

/* 跳过 UTF-8 BOM */
static const char *SkipBom(const char *p) {
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB &&
        (unsigned char)p[2] == 0xBF)
        return p + 3;
    return p;
}

static int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ------------------------------------------------------------------ */
/* 迷你 JSON 解析(容错、有界,覆盖本场景所需)                        */
/* ------------------------------------------------------------------ */

static void JsonPut(char *out, size_t n, size_t *o, char c) {
    if (out && *o + 1 < n)
        out[*o] = c;
    (*o)++;
}

/* 解析 JSON 字符串(支持转义与 \uXXXX,含代理对)。*pp 指向起始引号。 */
static bool JsonString(const char **pp, char *out, size_t n) {
    const char *p = *pp;
    if (!p || *p != '"')
        return false;
    p++;
    size_t o = 0;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p++;
        if (c == '\\') {
            char e = *p++;
            switch (e) {
                case 'n': JsonPut(out, n, &o, '\n'); break;
                case 'r': JsonPut(out, n, &o, '\r'); break;
                case 't': JsonPut(out, n, &o, '\t'); break;
                case 'b': JsonPut(out, n, &o, '\b'); break;
                case 'f': JsonPut(out, n, &o, '\f'); break;
                case '/': JsonPut(out, n, &o, '/');  break;
                case '"': JsonPut(out, n, &o, '"');  break;
                case '\\': JsonPut(out, n, &o, '\\'); break;
                case 'u': {
                    if (HexVal(p[0]) < 0 || HexVal(p[1]) < 0 || HexVal(p[2]) < 0 || HexVal(p[3]) < 0)
                        return false;
                    u32 cp = (u32)((HexVal(p[0]) << 12) | (HexVal(p[1]) << 8) |
                                   (HexVal(p[2]) << 4) | HexVal(p[3]));
                    p += 4;
                    if (cp >= 0xD800 && cp <= 0xDBFF && p[0] == '\\' && p[1] == 'u' &&
                        HexVal(p[2]) >= 0 && HexVal(p[3]) >= 0 &&
                        HexVal(p[4]) >= 0 && HexVal(p[5]) >= 0) {
                        u32 lo = (u32)((HexVal(p[2]) << 12) | (HexVal(p[3]) << 8) |
                                       (HexVal(p[4]) << 4) | HexVal(p[5]));
                        if (lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                            p += 6;
                        }
                    }
                    if (cp < 0x80) {
                        JsonPut(out, n, &o, (char)cp);
                    } else if (cp < 0x800) {
                        JsonPut(out, n, &o, (char)(0xC0 | (cp >> 6)));
                        JsonPut(out, n, &o, (char)(0x80 | (cp & 0x3F)));
                    } else if (cp < 0x10000) {
                        JsonPut(out, n, &o, (char)(0xE0 | (cp >> 12)));
                        JsonPut(out, n, &o, (char)(0x80 | ((cp >> 6) & 0x3F)));
                        JsonPut(out, n, &o, (char)(0x80 | (cp & 0x3F)));
                    } else {
                        JsonPut(out, n, &o, (char)(0xF0 | (cp >> 18)));
                        JsonPut(out, n, &o, (char)(0x80 | ((cp >> 12) & 0x3F)));
                        JsonPut(out, n, &o, (char)(0x80 | ((cp >> 6) & 0x3F)));
                        JsonPut(out, n, &o, (char)(0x80 | (cp & 0x3F)));
                    }
                    break;
                }
                default: JsonPut(out, n, &o, e); break;
            }
        } else {
            JsonPut(out, n, &o, (char)c);
        }
    }
    if (*p != '"')
        return false;
    p++;
    if (out && n > 0)
        out[o < n ? o : n - 1] = 0;
    *pp = p;
    return true;
}

/* 跳过一个完整 JSON 值,返回其后位置;失败返回 nullptr。 */
static const char *JsonSkip(const char *p, int depth) {
    if (!p || depth > 24)
        return nullptr;
    p = JsWs(p);
    switch (*p) {
        case '"':
            return JsonString(&p, nullptr, 0) ? p : nullptr;
        case '{':
        case '[': {
            char close = (*p == '{') ? '}' : ']';
            p = JsWs(p + 1);
            if (*p == close)
                return p + 1;
            for (;;) {
                if (close == '}') {
                    p = JsonSkip(p, depth + 1);          /* key */
                    if (!p) return nullptr;
                    p = JsWs(p);
                    if (*p != ':') return nullptr;
                    p = JsonSkip(p + 1, depth + 1);      /* value */
                } else {
                    p = JsonSkip(p, depth + 1);
                }
                if (!p) return nullptr;
                p = JsWs(p);
                if (*p == ',') { p = JsWs(p + 1); continue; }
                if (*p == close) return p + 1;
                return nullptr;
            }
        }
        case 't': return (strncmp(p, "true", 4) == 0) ? p + 4 : nullptr;
        case 'f': return (strncmp(p, "false", 5) == 0) ? p + 5 : nullptr;
        case 'n': return (strncmp(p, "null", 4) == 0) ? p + 4 : nullptr;
        default: {
            const char *s = p;
            if (*p == '-' || *p == '+') p++;
            bool any = false;
            while ((*p >= '0' && *p <= '9') || *p == '.' || *p == 'e' ||
                   *p == 'E' || *p == '-' || *p == '+') {
                p++;
                any = true;
            }
            return (any && p != s) ? p : nullptr;
        }
    }
}

/* 在 obj(指向 '{')中取 key 对应值的起始位置;没有则 nullptr。 */
static const char *JsonGet(const char *obj, const char *key) {
    if (!obj || *obj != '{')
        return nullptr;
    const char *p = JsWs(obj + 1);
    if (*p == '}')
        return nullptr;
    for (;;) {
        char k[64];
        if (*p != '"' || !JsonString(&p, k, sizeof(k)))
            return nullptr;
        p = JsWs(p);
        if (*p != ':')
            return nullptr;
        p = JsWs(p + 1);
        if (strcmp(k, key) == 0)
            return p;
        p = JsonSkip(p, 1);
        if (!p)
            return nullptr;
        p = JsWs(p);
        if (*p == ',') { p = JsWs(p + 1); continue; }
        return nullptr;
    }
}

static bool JsonGetStr(const char *obj, const char *key, char *out, size_t n) {
    const char *v = JsonGet(obj, key);
    return v && *v == '"' && JsonString(&v, out, n);
}

static bool JsonGetU32(const char *obj, const char *key, u32 *out) {
    const char *v = JsonGet(obj, key);
    if (!v)
        return false;
    v = JsWs(v);
    if (*v < '0' || *v > '9')
        return false;
    u32 acc = 0;
    while (*v >= '0' && *v <= '9') {
        if (acc < 0x0CCCCCCC)
            acc = acc * 10 + (u32)(*v - '0');
        v++;
    }
    *out = acc;
    return true;
}

/* 同义 key 依次尝试(如 contentId/content_id) */
static bool JsonGetStrAny(const char *obj, const char *k1, const char *k2,
                          char *out, size_t n) {
    if (JsonGetStr(obj, k1, out, n))
        return true;
    return k2 && JsonGetStr(obj, k2, out, n);
}

/* ------------------------------------------------------------------ */
/* HTTP 客户端(纯 HTTP;Content-Length / chunked / 连接关闭三种定界)   */
/* ------------------------------------------------------------------ */

struct HttpUrl {
    char host[96];
    u16  port;
    char path[320];
};

static bool HttpParseUrl(const char *url, HttpUrl *out) {
    if (strncmp(url, "http://", 7) != 0)
        return false;
    const char *p = url + 7;
    const char *slash = strchr(p, '/');
    const char *hostEnd = slash ? slash : p + strlen(p);
    const char *colon = (const char *)memchr(p, ':', (size_t)(hostEnd - p));
    size_t hostLen = (size_t)((colon ? colon : hostEnd) - p);
    if (hostLen == 0 || hostLen >= sizeof(out->host))
        return false;
    memcpy(out->host, p, hostLen);
    out->host[hostLen] = 0;
    out->port = 80;
    if (colon) {
        u32 port = 0;
        const char *q = colon + 1;
        while (q < hostEnd && *q >= '0' && *q <= '9')
            port = port * 10 + (u32)(*q++ - '0');
        if (port == 0 || port > 65535)
            return false;
        out->port = (u16)port;
    }
    if (!slash) {
        out->path[0] = '/';
        out->path[1] = 0;
    } else {
        size_t plen = strlen(slash);
        if (plen >= sizeof(out->path))
            return false;
        memcpy(out->path, slash, plen + 1);
    }
    return true;
}

/* libnx/newlib 的 netinet/in.h 不定义 INADDR_NONE,补一个 */
#ifndef INADDR_NONE
#define INADDR_NONE ((in_addr_t)0xFFFFFFFFu)
#endif

/* ------------------------------------------------------------------ */
/* 原始 UDP DNS(与 sysmodule relay_client 同款)。
 * 真机诊断:覆盖层进程里 getaddrinfo 全部失败(refresh 里所有 e=1),
 * 而 sysmodule 的延迟测量一直正常——它从来不用 getaddrinfo,而是手工
 * 构造 DNS 报文发给路由器通告的 DNS(nifmGetCurrentIpConfigInfo)。
 * 这里照搬该实现;nifm 拿不到 dns 时退公网 DNS(国内 223.5.5.5/
 * 114.114.114.114,海外 8.8.8.8/1.1.1.1)。 */
/* ------------------------------------------------------------------ */

static u32 DnsBe32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

/* 构造 A 查询报文;成功返回长度,失败 0。 */
static size_t DnsBuildQuery(const char *host, u8 *q, size_t cap, u8 txid0, u8 txid1) {
    if (host == nullptr || host[0] == '\0' || cap < 18)
        return 0;
    q[0] = txid0; q[1] = txid1;
    q[2] = 0x01; q[3] = 0x00;                 /* RD */
    q[4] = 0x00; q[5] = 0x01;                 /* qdcount=1 */
    q[6] = q[7] = q[8] = q[9] = q[10] = q[11] = 0;
    size_t p = 12;
    const char *s = host;
    while (*s != '\0') {
        const char *dot = strchr(s, '.');
        size_t len = dot ? (size_t)(dot - s) : strlen(s);
        if (len == 0 || len > 63 || p + len + 6 > cap)
            return 0;
        q[p++] = (u8)len;
        memcpy(q + p, s, len);
        p += len;
        s += len;
        if (*s == '.')
            s++;
    }
    q[p++] = 0x00;
    q[p++] = 0x00; q[p++] = 0x01;             /* A    */
    q[p++] = 0x00; q[p++] = 0x01;             /* IN   */
    return p;
}

/* 跳过一个域名(标签串或 0xC0 压缩指针)。 */
static bool DnsSkipName(const u8 *r, ssize_t n, size_t *off) {
    for (;;) {
        if (*off >= (size_t)n)
            return false;
        u8 c = r[*off];
        if ((c & 0xc0) == 0xc0) {
            *off += 2;
            return true;
        }
        if (c == 0) {
            *off += 1;
            return true;
        }
        *off += (size_t)c + 1;
    }
}

/* 解析应答,取第一个 A 记录;*ipNet 为网络字序。 */
static bool DnsParseA(const u8 *r, ssize_t n, u8 txid0, u8 txid1, u32 *ipNet) {
    if (n < 12)
        return false;
    if (r[0] != txid0 || r[1] != txid1)
        return false;
    if ((r[2] & 0x80) == 0)                   /* QR */
        return false;
    if ((r[3] & 0x0f) != 0)                   /* RCODE */
        return false;
    int ancount = (r[6] << 8) | r[7];
    if (ancount < 1)
        return false;

    size_t off = 12;
    if (!DnsSkipName(r, n, &off))
        return false;
    off += 4;                                 /* qtype + qclass */
    if (off > (size_t)n)
        return false;

    for (int i = 0; i < ancount && off + 12 <= (size_t)n; i++) {
        if (!DnsSkipName(r, n, &off))
            return false;
        if (off + 10 > (size_t)n)
            break;
        int type  = (r[off] << 8) | r[off + 1];
        int rdlen = (r[off + 8] << 8) | r[off + 9];
        off += 10;
        if (type == 1 && rdlen == 4 && off + 4 <= (size_t)n) {
            *ipNet = htonl(DnsBe32(r + off));
            return true;
        }
        off += rdlen;
    }
    return false;
}

/* 向单个 DNS 服务器查 A;返回主机字序 IP,0=失败。 */
static u32 DnsQueryServer(u32 srvHost, const char *host, u8 txid0, u8 txid1) {
    u8 q[300];
    size_t qlen = DnsBuildQuery(host, q, sizeof(q), txid0, txid1);
    if (qlen == 0)
        return 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    sa.sin_addr.s_addr = htonl(srvHost);
    /* devkitA64 的 newlib 没有 MSG_DONTWAIT,非阻塞只能走 O_NONBLOCK
     * (fcntl)。设成非阻塞后 recvfrom 无数据返回 -1 + EAGAIN,再配合下面
     * 10ms 一轮的等待循环,就能随时被中止标志打断。 */
    {
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0)
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
    u32 ip = 0;
    if (sendto(fd, q, (int)qlen, 0, (struct sockaddr *)&sa, sizeof(sa)) >= 0) {
        u8 r[512];
        /* 分片等待:一旦用户返回/退出就立刻跳出,不等满 2 秒超时 */
        ssize_t n = -1;
        for (int wait = 0; wait < 20 * 10; wait++) {
            if (IoAbort())
                break;
            n = recvfrom(fd, r, sizeof(r), 0, nullptr, nullptr);
            if (n > 0)
                break;
            svcSleepThread(10'000'000);          /* 10ms */
        }
        if (n > 0) {
            u32 net = 0;
            if (DnsParseA(r, n, txid0, txid1, &net))
                ip = ntohl(net);
        }
    }
    close(fd);
    return ip;
}

static u32 g_dnsSrv[6];
static int g_dnsSrvN = 0;
static bool g_dnsSrvReady = false;
static u32 g_dnsNifmRc = 1;                   /* 0=ok,其它=失败码 */

static void DnsInitServers() {
    if (g_dnsSrvReady)
        return;
    g_dnsSrvReady = true;
    u32 a = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
    Result rc = nifmInitialize(NifmServiceType_User);
    if (R_FAILED(rc))
        rc = nifmInitialize(NifmServiceType_System);
    if (R_SUCCEEDED(rc)) {
        g_dnsNifmRc = 0;
        if (R_SUCCEEDED(nifmGetCurrentIpConfigInfo(&a, &mask, &gw, &dns1, &dns2))) {
            if (dns1 != 0)
                g_dnsSrv[g_dnsSrvN++] = ntohl(dns1);
            if (dns2 != 0)
                g_dnsSrv[g_dnsSrvN++] = ntohl(dns2);
        }
        nifmExit();
    } else {
        g_dnsNifmRc = (u32)rc;
    }
    /* 公网兜底:国内两台 + 海外两台 */
    g_dnsSrv[g_dnsSrvN++] = 0xDF050505u;      /* 223.5.5.5 */
    g_dnsSrv[g_dnsSrvN++] = 0x72727272u;      /* 114.114.114.114 */
    g_dnsSrv[g_dnsSrvN++] = 0x08080808u;      /* 8.8.8.8 */
    g_dnsSrv[g_dnsSrvN++] = 0x01010101u;      /* 1.1.1.1 */
    char m[96];
    snprintf(m, sizeof(m), "dns srv nifm=%08x n=%d",
             (unsigned)g_dnsNifmRc, g_dnsSrvN);
    MonLog(m);
}

struct DnsEnt {
    char host[64];
    u32 ip;                                   /* 主机字序 */
};
static DnsEnt g_dnsCache[32];   /* 覆盖 MONITOR_MAX_SERVERS(32),避免多台轮转时驱逐重查 */
static int g_dnsCacheN = 0;

static bool DnsResolve(const char *host, u32 *ipNet) {
    DnsInitServers();
    for (int i = 0; i < g_dnsCacheN; i++) {
        if (strcasecmp(g_dnsCache[i].host, host) == 0 && g_dnsCache[i].ip != 0) {
            *ipNet = htonl(g_dnsCache[i].ip);
            return true;
        }
    }
    for (int s = 0; s < g_dnsSrvN; s++) {
        if (IoAbort())
            return false;
        u32 ip = DnsQueryServer(g_dnsSrv[s], host, 0x13, 0x37);
        if (ip != 0) {
            if (g_dnsCacheN < (int)(sizeof(g_dnsCache) / sizeof(g_dnsCache[0]))) {
                snprintf(g_dnsCache[g_dnsCacheN].host,
                         sizeof(g_dnsCache[0].host), "%s", host);
                g_dnsCache[g_dnsCacheN].ip = ip;
                g_dnsCacheN++;
            }
            *ipNet = htonl(ip);
            char m[96];
            snprintf(m, sizeof(m), "dns ok %s %08x", host, (unsigned)ip);
            MonLog(m);
            return true;
        }
    }
    char m[64];
    snprintf(m, sizeof(m), "dns raw fail %s", host);
    MonLog(m);
    return false;
}

static bool HttpResolve(const char *host, struct sockaddr_in *sa) {
    if (IoAbort())
        return false;
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    u32 ip = inet_addr(host);
    if (ip != (u32)INADDR_NONE && ip != 0) {
        sa->sin_addr.s_addr = ip;
        return true;
    }
    /* 1) 原始 UDP DNS(sysmodule 同款,真机可用) */
    if (DnsResolve(host, &sa->sin_addr.s_addr))
        return true;
    if (IoAbort())
        return false;
    /* 2) getaddrinfo 兜底(真机通常失败,保留无害) */
    /* libnx/newlib 没有 gethostbyname,域名解析用 getaddrinfo */
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res)
        return false;
    memcpy(&sa->sin_addr, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
           sizeof(sa->sin_addr));
    freeaddrinfo(res);
    return true;
}

static void HttpSetNonBlock(int fd, bool nb) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0)
        return;
    fcntl(fd, F_SETFL, nb ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
}

using Deadline = std::chrono::steady_clock::time_point;

static bool HttpSendAll(int fd, const char *buf, size_t len, const Deadline &deadline) {
    size_t off = 0;
    while (off < len) {
        if (std::chrono::steady_clock::now() >= deadline || IoAbort())
            return false;
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10 * 1000;
        int sel = select(fd + 1, nullptr, &wset, nullptr, &tv);
        if (sel < 0)
            return false;
        if (sel == 0)
            continue;
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0)
            return false;
        off += (size_t)n;
    }
    return true;
}

static bool HttpIsChunked(const std::string &headersLower) {
    size_t te = headersLower.find("transfer-encoding:");
    if (te == std::string::npos)
        return false;
    size_t lineEnd = headersLower.find("\r\n", te);
    size_t ck = headersLower.find("chunked", te);
    return ck != std::string::npos && (lineEnd == std::string::npos || ck < lineEnd);
}

/* 发起请求,响应(头+体)收进 raw。 */
/* HTTP 传输错误码(诊断用):0=ok 1=resolve 2=socket 3=connect 4=timeout
 * 5=io 6=aborted(返回/退出时主动中止);≥100 表示 HTTP 状态码。 */
static int g_httpErr = 0;
/* 最近一次 HTTP 请求从发起连接到收到首个响应字节折算的单程往返 RTT(毫秒)。
 * 新建短连接从 connect 开始到收到首字节必经 2 个真实网络 RTT(TCP 握手 + HTTP 问答),
 * 即便真机 bsd:u 或透明代理使 connect 提前本地返回,totalMs / 2 依然等于真实 1 RTT,
 * 可在个别服务器未开启 UDP PING 回显时作为准确的延迟兜底。 */
static s32 g_httpRttMs = 0;

static bool HttpExchange(const char *host, u16 port, const char *req, size_t reqLen,
                         std::string &raw, size_t maxBody, int timeoutMs) {
    g_httpErr = 0;
    g_httpRttMs = 0;
    if (IoAbort()) {
        g_httpErr = 6;
        return false;
    }
    struct sockaddr_in sa;
    if (!HttpResolve(host, &sa)) {
        g_httpErr = IoAbort() ? 6 : 1;
        return false;
    }
    sa.sin_port = htons(port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        g_httpErr = 2;
        return false;
    }

    Deadline connStart = std::chrono::steady_clock::now();
    Deadline deadline = connStart + std::chrono::milliseconds(timeoutMs);

    /* 非阻塞 connect + 10ms 分片 select,任何时刻按返回键都能在 10ms 内打断 */
    HttpSetNonBlock(fd, true);
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc != 0) {
        for (;;) {
            if (IoAbort()) {
                g_httpErr = 6;
                close(fd);
                return false;
            }
            long left = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) {
                g_httpErr = 4;
                close(fd);
                return false;
            }
            fd_set wset;
            FD_ZERO(&wset);
            FD_SET(fd, &wset);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = (left < 10 ? left : 10) * 1000;
            int sel = select(fd + 1, nullptr, &wset, nullptr, &tv);
            if (sel < 0) {
                g_httpErr = 3;
                close(fd);
                return false;
            }
            if (sel == 0)
                continue;
            int err = 0;
            socklen_t elen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
                g_httpErr = 3;
                close(fd);
                return false;
            }
            break;
        }
    }

    if (!HttpSendAll(fd, req, reqLen, deadline)) {
        g_httpErr = IoAbort() ? 6 : 5;
        close(fd);
        return false;
    }

    raw.clear();
    char buf[2048];
    bool gotFirstByte = false;
    bool haveHeaders = false;
    bool chunked = false;
    long contentLength = -1;
    size_t headerEnd = 0;

    /* 收包循环改成短超时轮询 + 每轮检查中止标志:
     * 以前 recv 会一口气卡到超时(最长 6 秒),用户按返回时特斯拉菜单就要等
     * 这一整轮查询跑完才出来 —— 这就是"返回还是要过一会"的主因之一。 */
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline) {
            /* 超时:已有完整响应体则接受,否则失败 */
            if (haveHeaders)
                break;
            g_httpErr = 4;
            close(fd);
            return false;
        }
        if (IoAbort()) {
            g_httpErr = 6;
            close(fd);
            return false;
        }
        /* 先 select 等 10ms 再看有没有数据:这样既能每 10ms 检查一次中止
         * 标志,又不用依赖 errno。libnx 的 bsd 把错误放在线程私有的
         * g_bsdErrno 里,不写 newlib 的 errno,靠 errno 判断 EAGAIN 不可靠。 */
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        struct timeval wtv;
        wtv.tv_sec = 0;
        wtv.tv_usec = 10 * 1000;
        int sel = select(fd + 1, &rset, nullptr, nullptr, &wtv);
        if (sel < 0) {
            if (haveHeaders)
                break;
            g_httpErr = 5;
            close(fd);
            return false;
        }
        if (sel == 0)
            continue;                                /* 还没数据:回去查中止标志 */
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (haveHeaders)
                break;
            g_httpErr = 5;
            close(fd);
            return false;
        }
        if (n == 0)
            break;                                   /* 对端关闭:EOF 定界 */
        if (!gotFirstByte) {
            gotFirstByte = true;
            s32 totalMs = (s32)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - connStart).count();
            s32 rtt = totalMs / 2;
            g_httpRttMs = rtt > 0 ? rtt : 1;
        }
        if (raw.size() + (size_t)n > maxBody + 8192) {
            close(fd);
            return false;
        }
        raw.append(buf, (size_t)n);

        if (!haveHeaders) {
            size_t pos = raw.find("\r\n\r\n");
            if (pos == std::string::npos)
                continue;
            headerEnd = pos + 4;
            haveHeaders = true;

            std::string headersLower = raw.substr(0, pos);
            for (auto &ch : headersLower)
                ch = (char)tolower((unsigned char)ch);
            chunked = HttpIsChunked(headersLower);
            size_t cl = headersLower.find("content-length:");
            if (cl != std::string::npos) {
                contentLength = atol(headersLower.c_str() + cl + 15);
                if (contentLength < 0)
                    contentLength = 0;
            }
            /* 按 Content-Length 精确预留,避免 std::string 几何增长
             * 产生约 2 倍的瞬时容量(挤爆 ovlloader 的小堆)。 */
            if (!chunked && contentLength > 0 &&
                (size_t)contentLength <= maxBody)
                raw.reserve(headerEnd + (size_t)contentLength);
        }
        if (haveHeaders && contentLength >= 0 && !chunked &&
            raw.size() >= headerEnd + (size_t)contentLength)
            break;
    }
    close(fd);
    return haveHeaders;
}

/* 解析响应:状态码 + body(chunked 已解码;Content-Length 已截断)。 */
static bool HttpParseResponse(std::string &raw, int *outStatus, std::string *outBody) {
    size_t pos = raw.find("\r\n\r\n");
    if (pos == std::string::npos)
        return false;
    const char *sp = strchr(raw.c_str(), ' ');
    if (!sp)
        return false;
    *outStatus = atoi(sp + 1);

    std::string headersLower = raw.substr(0, pos);
    for (auto &ch : headersLower)
        ch = (char)tolower((unsigned char)ch);

    std::string body;
    size_t p = pos + 4;
    if (HttpIsChunked(headersLower)) {
        for (;;) {
            size_t eol = raw.find("\r\n", p);
            if (eol == std::string::npos)
                return false;
            unsigned long chunk = strtoul(raw.c_str() + p, nullptr, 16);
            if (chunk == 0)
                break;                    /* 尾块:忽略 trailer */
            p = eol + 2;
            if (chunk > raw.size() || p + chunk + 2 > raw.size())
                return false;
            body.append(raw, p, chunk);
            p += chunk + 2;
        }
    } else {
        /* 原地截掉响应头并搬走,避免 body 再复制一份
         * (overlay 堆只有几 MB,少一次订阅文件大小的峰值拷贝)。 */
        raw.erase(0, p);
        size_t cl = headersLower.find("content-length:");
        if (cl != std::string::npos) {
            long n = atol(headersLower.c_str() + cl + 15);
            if (n >= 0 && (size_t)n < raw.size())
                raw.resize((size_t)n);
        }
        *outBody = std::move(raw);
        return true;
    }
    *outBody = std::move(body);
    return true;
}

static bool HttpGet(const char *url, std::string *outBody, int timeoutMs, size_t maxBody) {
    HttpUrl u;
    if (!HttpParseUrl(url, &u))
        return false;
    char req[768];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: %s:%u\r\nUser-Agent: ldn_mitm-overlay\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n",
                     u.path, u.host, (unsigned)u.port);
    if (n <= 0 || n >= (int)sizeof(req))
        return false;
    std::string raw;
    if (!HttpExchange(u.host, u.port, req, (size_t)n, raw, maxBody, timeoutMs))
        return false;
    int status = 0;
    if (!HttpParseResponse(raw, &status, outBody))
        return false;
    if (status >= 200 && status < 300)
        return true;
    g_httpErr = 100 + status;
    return false;
}

static bool HttpPostJson(const char *url, const char *json,
                         std::string *outBody, int timeoutMs, size_t maxBody) {
    HttpUrl u;
    if (!HttpParseUrl(url, &u))
        return false;
    size_t jlen = strlen(json);
    char req[512];
    int n = snprintf(req, sizeof(req),
                     "POST %s HTTP/1.1\r\nHost: %s:%u\r\nUser-Agent: ldn_mitm-overlay\r\n"
                     "Content-Type: application/json\r\nAccept: application/json\r\n"
                     "Connection: close\r\nContent-Length: %u\r\n\r\n",
                     u.path, u.host, (unsigned)u.port, (unsigned)jlen);
    if (n <= 0 || n >= (int)sizeof(req))
        return false;
    std::string full;
    full.assign(req, (size_t)n);
    full.append(json, jlen);
    std::string raw;
    if (!HttpExchange(u.host, u.port, full.c_str(), full.size(), raw, maxBody, timeoutMs))
        return false;
    int status = 0;
    if (!HttpParseResponse(raw, &status, outBody))
        return false;
    if (status >= 200 && status < 300)
        return true;
    g_httpErr = 100 + status;
    return false;
}

/* HTTPS 通道(switch-curl,libnx SSL 后端):overlay 是纯 HTTP 客户端,
 * GitHub 全站强制 HTTPS,只有走 TLS 才能把订阅真正拉下来(v6.gh-proxy.org
 * 加速镜像就是 https)。DNS 用本文件的原始解析(覆盖层进程里 getaddrinfo
 * 不可用),以 CURLOPT_RESOLVE 钉住 IP,SNI/Host 仍是域名。 */
static bool s_curlInited = false;

static size_t CurlWrite(char *ptr, size_t size, size_t nmemb, void *userdata) {
    std::string *out = (std::string *)userdata;
    size_t n = size * nmemb;
    if (out->size() + n > kMaxDownload)
        return 0;
    out->append(ptr, n);
    return n;
}

/* curl 进度回调:CURLE_ABORTED_BY_CALLBACK 让 perform 立刻返回,
 * 3MB 订阅下载不会在用户关掉插件后继续霸占 CPU/网络。 */
static int CurlAbort(void *, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    return IoAbort() ? 1 : 0;
}

static bool HttpsGet(const char *url, std::string *outBody, int timeoutMs) {
    if (strncmp(url, "https://", 8) != 0 || IoAbort())
        return false;
    EnsureSockets();
    if (!s_curlInited) {
        /* libnx SSL 后端经 sm 拿 ssl 服务;外层已开 sm 时失败也无妨 */
        bool ownSm = R_SUCCEEDED(smInitialize());
        curl_global_init(CURL_GLOBAL_DEFAULT);
        if (ownSm)
            smExit();
        s_curlInited = true;
    }
    /* 预解析 host:curl 默认 getaddrinfo 在 overlay 里全灭,必须钉 IP */
    const char *hostBeg = url + 8;
    const char *hostEnd = strchr(hostBeg, '/');
    size_t hl = hostEnd ? (size_t)(hostEnd - hostBeg) : strlen(hostBeg);
    char host[128];
    if (hl == 0 || hl >= sizeof(host))
        return false;
    memcpy(host, hostBeg, hl);
    host[hl] = 0;
    struct sockaddr_in sa = {};
    if (!HttpResolve(host, &sa) || IoAbort())
        return false;
    char resolve[192];
    snprintf(resolve, sizeof(resolve), "%s:443:%u.%u.%u.%u", host,
             (unsigned)(sa.sin_addr.s_addr & 0xFF),
             (unsigned)((sa.sin_addr.s_addr >> 8) & 0xFF),
             (unsigned)((sa.sin_addr.s_addr >> 16) & 0xFF),
             (unsigned)((sa.sin_addr.s_addr >> 24) & 0xFF));

    outBody->clear();
    CURL *curl = curl_easy_init();
    if (!curl)
        return false;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    /* CURLOPT_RESOLVE 收的是 struct curl_slist *,不是 char *(curl 7.69 同)。
     * 传字符串会把地址当链表头解引用,首次 perform 即崩(2168-0002)——
     * 10-19 设备报错正死在这一窗口。 */
    struct curl_slist *lst = curl_slist_append(nullptr, resolve);
    if (!lst) {
        curl_easy_cleanup(curl);
        return false;
    }
    curl_easy_setopt(curl, CURLOPT_RESOLVE, lst);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, outBody);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, (long)kMaxDownload);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2500L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeoutMs);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlAbort);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ldn-mitm-monitor");
    MonLog("curl-try");
    CURLcode rc = curl_easy_perform(curl);
    {
        char m[48];
        snprintf(m, sizeof(m), "curl-done rc=%d", (int)rc);
        MonLog(m);
    }
    curl_slist_free_all(lst);          /* perform 结束后才可释放 */
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    if (rc == CURLE_OK && status >= 200 && status < 300)
        return true;
    /* 错误码:700+curlcode(curl 层),否则 100+HTTP 状态 */
    g_httpErr = (rc != CURLE_OK) ? (700 + (int)rc) : (100 + (int)status);
    outBody->clear();
    return false;
}

/* 按镜像链下载订阅文件(https 镜像走 curl,http 兜底走内置轻客户端) */
static bool DownloadSubscription(const char *relPath, std::string *out) {
    for (size_t i = 0; i < sizeof(kUrlPrefixes) / sizeof(kUrlPrefixes[0]); i++) {
        if (IoAbort())
            return false;
        char url[512];
        snprintf(url, sizeof(url), "%s%s", kUrlPrefixes[i], relPath);
        bool ok = (strncmp(url, "https://", 8) == 0)
                      ? HttpsGet(url, out, 5000)
                      : HttpGet(url, out, 5000, kMaxDownload);
        if (ok) {
            MonLog("download ok");
            return true;
        }
        char msg[40];
        snprintf(msg, sizeof(msg), "download try fail e=%d", g_httpErr);
        MonLog(msg);
    }
    return false;
}

static void SaveFile(const char *path, const std::string &data) {
    EnsureSd();
    mkdir("sdmc:/config", 0777);
    mkdir(kSaveDir, 0777);
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    fwrite(data.data(), 1, data.size(), f);
    fclose(f);
}

static bool LoadFile(const char *path, std::string *out) {
    EnsureSd();
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    char buf[4096];
    out->clear();
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), f);
        if (n == 0)
            break;
        if (out->size() + n > kMaxDownload) {
            fclose(f);
            return false;
        }
        out->append(buf, n);
    }
    fclose(f);
    return !out->empty();
}

/* ------------------------------------------------------------------ */
/* 订阅解析:chinese_db.json(servers.json 已移除) */
/* ------------------------------------------------------------------ */

static u64 TitleKeyPack(const char *hex16) {
    u64 key = 0;
    for (int i = 0; i < 16; i++) {
        int v = HexVal(hex16[i]);
        if (v < 0)
            return 0;
        key = (key << 4) | (u64)v;
    }
    return key;
}

static u32 TitleHash(u64 key) {
    key ^= key >> 33;
    key *= 0xFF51AFD7ED558CCDull;
    key ^= key >> 33;
    return (u32)key & (kTitleHashSize - 1);
}

static void TitleInsert(u64 key, const char *name, size_t nameLen) {
    if (!g_titleKey || key == 0)
        return;
    u32 idx = TitleHash(key);
    for (u32 probe = 0; probe < kTitleHashSize; probe++) {
        u32 i = (idx + probe) & (kTitleHashSize - 1);
        if (g_titleKey[i] == 0) {
            if (g_titleArenaUsed + nameLen + 1 > kTitleArena)
                return;
            u32 off = g_titleArenaUsed;
            memcpy(g_titleArena + off, name, nameLen);
            g_titleArena[off + nameLen] = 0;
            g_titleArenaUsed = off + (u32)nameLen + 1;
            g_titleOff[i] = off;
            g_titleLen[i] = (u16)nameLen;
            g_titleKey[i] = key + 1;
            return;
        }
        if (g_titleKey[i] == key + 1)
            return;                      /* 重复 key:保留先到的 */
    }
}

static const char *TitleLookup(u64 key, size_t *outLen) {
    if (!g_titleKey || key == 0)
        return nullptr;
    u32 idx = TitleHash(key);
    for (u32 probe = 0; probe < kTitleHashSize; probe++) {
        u32 i = (idx + probe) & (kTitleHashSize - 1);
        if (g_titleKey[i] == 0)
            return nullptr;
        if (g_titleKey[i] == key + 1) {
            if (outLen)
                *outLen = g_titleLen[i];
            return g_titleArena + g_titleOff[i];
        }
    }
    return nullptr;
}

/* (整读 JSON 的旧解析器已由 ParseChineseDbFile 流式版取代) */

/* 从文件流式解析 {"KEY":"NAME",...} 到标题表。
 * 不把 480KB 的订阅 JSON 整个读进 std::string——窗口只有 1KB,
 * 峰值内存 = 标题表(约 512KB) + 窗口,避免与订阅字符串叠加把
 * ovlloader 仅几 MB 的堆挤爆(0x559 OutOfMemory)。 */
static bool ParseChineseDbFile(const char *path) {
    EnsureSd();
    EnsureTitleTables();          /* 幂等:不依赖调用方先建表 */
    if (!g_titleKey)
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    char win[1280];
    size_t winLen = 0;
    bool eof = false, atStart = true;

    while (!eof || winLen > 0) {
        if (IoAbort()) {
            fclose(f);
            return false;
        }
        if (!eof && winLen < sizeof(win) - 1) {
            size_t n = fread(win + winLen, 1, sizeof(win) - 1 - winLen, f);
            if (n == 0)
                eof = true;
            winLen += n;
        }
        if (winLen >= sizeof(win))
            winLen = sizeof(win) - 1;
        win[winLen] = '\0';

        const char *p = win;
        if (atStart) {
            p = JsWs(SkipBom(p));
            if (*p == '{')
                p = JsWs(p + 1);
            else if (*p == '\0' && !eof)
                continue;                 /* 数据未到 */
            atStart = false;
        }

        bool advanced = true;
        while (advanced) {
            advanced = false;
            p = JsWs(p);
            if (*p == '\0')
                break;                    /* 窗口尾:等更多数据 */
            if (*p == '}')
                { fclose(f); return true; }
            if (*p == ',')
                { p++; advanced = true; continue; }
            if (*p != '"')
                { p++; advanced = true; continue; }   /* 容错跳过 */

            const char *q = p;
            char key[24], name[128];
            if (!JsonString(&q, key, sizeof(key)))
                break;                    /* 不完整(跨块)或坏转义 */
            q = JsWs(q);
            if (*q != ':')
                break;
            q = JsWs(q + 1);
            if (!JsonString(&q, name, sizeof(name)))
                break;

            u64 k = TitleKeyPack(key);
            if (k != 0 && name[0])
                TitleInsert(k, name, strlen(name));
            p = q;
            advanced = true;
        }

        size_t used = (size_t)(p - win);
        if (used > 0) {
            memmove(win, win + used, winLen - used);
            winLen -= used;
        }
        if (!advanced && !eof && winLen == sizeof(win) - 1) {
            /* 病态长 token 塞满窗口:丢一字节防止死锁 */
            memmove(win, win + 1, --winLen);
        }
        if (eof && !advanced)
            break;
    }
    fclose(f);
    return true;
}

/* ------------------------------------------------------------------ */
/* relay.cfg 行解析:与 sysmodule(relay_client.cpp LoadConfig)逐条对齐  */
/* ------------------------------------------------------------------ */

/* 指令值:LoadConfig 的 DirectiveValue 语义(name 后可接 =/空白,值再跳过)。 */
static const char *RelayDirective(const char *l, const char *name) {
    size_t n = strlen(name);
    if (strncmp(l, name, n) != 0)
        return nullptr;
    char c = l[n];
    if (c != 0 && c != '=' && c != ' ' && c != '\t')
        return nullptr;
    const char *v = l + n;
    while (*v == '=' || *v == ' ' || *v == '\t')
        v++;
    return v;
}

/* 解析 relay.cfg 的一行(服务器条目)。与 LoadConfig 完全同语义:
 *   sscanf("%31s %63s") —— 任意空白(含 \v \f)切 token;旧版用 " \t"
 *   切分,遇到 \v/\f 分隔的行就匹配不到名字(resolve noname 之谜);
 *   单 token 行 name=addr=token(随后 addr 再去 :port);
 *   enabled=/broadcast=/id=/selected= 指令行与 #/空行跳过;
 *   addr 可带 :port(默认 11451;port 为 0 或 >65535 整行丢弃)。
 * 返回 true = 是服务器行。 */
static bool RelayParseLine(const char *lineIn,
                           char *name, size_t nameN,
                           char *host, size_t hostN, u16 *port) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", lineIn);
    char *line = buf;
    while (*line == ' ' || *line == '\t')
        line++;
    if (*line == '#' || *line == 0)
        return false;
    if (RelayDirective(line, "enabled") || RelayDirective(line, "broadcast") ||
        RelayDirective(line, "selected") || RelayDirective(line, "id"))
        return false;

    char t1[32] = {}, t2[64] = {};
    if (sscanf(line, "%31s %63s", t1, t2) < 2) {
        if (sscanf(line, "%63s", t2) < 1)
            return false;
        snprintf(t1, sizeof(t1), "%.31s", t2);   /* 单 token:name=addr=token(同 %31s 截断) */
    }
    unsigned p = 11451;
    char *colon = strchr(t2, ':');
    if (colon) {
        *colon = 0;
        p = (unsigned)atoi(colon + 1);
    }
    if (t2[0] == 0 || p == 0 || p > 65535)
        return false;
    snprintf(name, nameN, "%s", t1);
    snprintf(host, hostN, "%s", t2);
    *port = (u16)p;
    return true;
}

/* 匹配 relay.cfg 一行里的服务器名;isEntry 标记该行是服务器行(指令/注释不算)。 */
static bool MatchRelayLine(const std::string &line, const char *want,
                           char *nameOut, size_t nameN,
                           char *hostOut, size_t hostN, u16 *portOut,
                           bool *isEntry = nullptr) {
    if (isEntry)
        *isEntry = false;
    char name[32] = {}, host[64] = {};
    u16 port = 0;
    if (!RelayParseLine(line.c_str(), name, sizeof(name), host, sizeof(host), &port))
        return false;
    if (isEntry)
        *isEntry = true;
    if (strcmp(name, want) != 0)
        return false;
    snprintf(nameOut, nameN, "%s", name);
    snprintf(hostOut, hostN, "%s", host);
    *portOut = port;
    return true;
}

/* 服务器列表:直接读 relay.cfg(与 sysmodule LoadConfig 同一套解析,
 * 第 i 条与 sysmodule 的 g_servers[i] 一一对应)。 */
u32 MonitorListRelayServers(MonitorServer *out, u32 max) {
    std::string cfg;
    if (!out || !LoadFile(kRelayCfgPath, &cfg))
        return 0;
    u32 n = 0;
    size_t i = 0;
    while (i < cfg.size() && n < max) {
        size_t e = cfg.find_first_of("\r\n", i);
        std::string line = cfg.substr(i, e == std::string::npos ? std::string::npos : e - i);
        i = (e == std::string::npos) ? cfg.size() : e + 1;
        char host[64] = {};
        u16 port = 0;
        if (RelayParseLine(line.c_str(), out[n].name, sizeof(out[n].name),
                           host, sizeof(host), &port)) {
            snprintf(out[n].addr, sizeof(out[n].addr), "%.55s:%u", host, (unsigned)port);
            n++;
        }
    }
    return n;
}

static bool ResolveSelectedServer(const char *nameOverride,
                                  char *nameOut, size_t nameN,
                                  char *hostOut, size_t hostN, u16 *portOut) {
    std::string cfg;
    if (!LoadFile(kRelayCfgPath, &cfg)) {
        MonLog("resolve FAIL cfg-missing");
        return false;
    }

    char want[64] = {};
    if (nameOverride && nameOverride[0])
        snprintf(want, sizeof(want), "%s", nameOverride);
    /* 名字去尾部空白(IPC/配置可能带填充;sysmodule 同样修剪) */
    for (int pass = 0; pass < 2; pass++) {
        size_t wl = strlen(want);
        while (wl > 0 && (want[wl - 1] == ' ' || want[wl - 1] == '\t'))
            want[--wl] = 0;
        if (pass == 0 && want[0])
            break;
        if (pass == 0 && !want[0]) {
            size_t pos = cfg.find("selected=");
            if (pos != std::string::npos) {
                size_t e = cfg.find_first_of("\r\n", pos);
                std::string line = cfg.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
                if (line.size() > 9)
                    snprintf(want, sizeof(want), "%s", line.c_str() + 9);
            }
        }
    }
    if (!want[0]) {
        MonLog("resolve FAIL no-name");
        return false;
    }

    int entryN = 0;
    char entries[80] = {};
    size_t i = 0;
    while (i < cfg.size()) {
        size_t e = cfg.find_first_of("\r\n", i);
        std::string line = cfg.substr(i, e == std::string::npos ? std::string::npos : e - i);
        i = (e == std::string::npos) ? cfg.size() : e + 1;

        bool isEntry = false;
        if (MatchRelayLine(line, want, nameOut, nameN, hostOut, hostN, portOut, &isEntry))
            return true;
        if (isEntry) {
            entryN++;
            char ename[32] = {}, ehost[64] = {};
            u16 eport = 0;
            if (RelayParseLine(line.c_str(), ename, sizeof(ename),
                               ehost, sizeof(ehost), &eport) &&
                strlen(entries) + strlen(ename) + 2 < sizeof(entries)) {
                strcat(entries, ename);
                strcat(entries, "|");
            }
        }
    }
    {
        char m[200];
        snprintf(m, sizeof(m), "resolve noname %s n=%d [%s]", want, entryN, entries);
        MonLog(m);
    }
    snprintf(nameOut, nameN, "%s", want);
    return false;
}

/* ------------------------------------------------------------------ */
/* 服务器查询:graphql / rest                                          */
/* ------------------------------------------------------------------ */

struct QueryResult {
    s32 online = -1;
    u32 roomN = 0;
    MonitorRoom rooms[MONITOR_MAX_ROOMS];
};

/* Room-specific advertiseData resolves all-F communication-ID sentinels.
 * Never substitute the local foreground ProgramId for a remote room: a server
 * can list several games, and that fallback would mislabel every such room. */
static void FormatGameName(const char *contentId, const char *advertiseData,
                           const char *hostPlayerName, char *out, size_t n) {
    char up[20] = {};
    size_t len = 0;
    for (const char *p = contentId; p && *p && len < 16; p++) {
        char c = *p;
        if (c >= 'a' && c <= 'f') c = (char)(c - 'a' + 'A');
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))
            up[len++] = c;
    }
    up[len] = 0;
    if (len != 16) {
        snprintf(out, n, "%s", T_STR("未知游戏", "未知遊戲"));
        return;
    }

    bool allOnes = true;
    for (size_t i = 0; i < 16; i++)
        allOnes &= (up[i] == 'F');
    if (allOnes) {
        char resolved[20] = {};
        if (!MonitorTitleResolver::ResolveAdvertisedTitleId(
                advertiseData, hostPlayerName, resolved, sizeof(resolved))) {
            snprintf(out, n, "%s", T_STR("未知游戏", "未知遊戲"));
            return;
        }
        snprintf(up, sizeof(up), "%s", resolved);
    }

    u64 key = TitleKeyPack(up);
    size_t nameLen = 0;
    const char *name = TitleLookup(key, &nameLen);
    if (name && name[0])
        snprintf(out, n, "%s", name);
    else
        snprintf(out, n, "%s", up);      /* 未映射:直接显示标题 ID */
}

/* room 对象数组 -> rooms[](graphql 与 rest 共用字段口径) */
static void ParseRoomArray(const char *arr, QueryResult *qr) {
    const char *p = JsWs(arr);
    if (*p != '[')
        return;
    p = JsWs(p + 1);
    while (qr->roomN < MONITOR_MAX_ROOMS && *p == '{') {
        MonitorRoom &r = qr->rooms[qr->roomN];
        memset(&r, 0, sizeof(r));
        char cid[24] = {};
        char advertiseData[MonitorTitleResolver::kAdvertiseDataMaxHex + 1] = {};
        char hostName[MONITOR_PLAYER_LEN + 1] = {};
        JsonGetStrAny(p, "contentId", "content_id", cid, sizeof(cid));
        JsonGetStrAny(p, "advertiseData", "advertise_data",
                      advertiseData, sizeof(advertiseData));
        JsonGetStrAny(p, "hostPlayerName", "host_player_name",
                      hostName, sizeof(hostName));
        FormatGameName(cid, advertiseData, hostName, r.game, sizeof(r.game));
        JsonGetStrAny(p, "sessionId", "session_id", r.sessionId, sizeof(r.sessionId));

        u32 v = 0;
        const bool hasPlayerCount =
            JsonGetU32(p, "nodeCount", &v) || JsonGetU32(p, "node_count", &v);
        if (hasPlayerCount)
            r.players = v;
        if (JsonGetU32(p, "nodeCountMax", &v) || JsonGetU32(p, "node_count_max", &v))
            r.playersMax = v;

        /* 玩家名单:hostPlayerName 排最前(UI 异色),再收节点名 */
        const char *nodes = JsonGet(p, "nodes");
        if (!nodes)
            nodes = JsonGet(p, "players");   /* rest 服务器的同义字段 */
        if (nodes && *nodes == '[') {
            const char *q = JsWs(nodes + 1);
            while (*q && *q != ']' && r.playerN < MONITOR_MAX_PLAYERS) {
                const char *next = JsonSkip(q, 1);
                if (!next)
                    break;
                if (*q == '{') {
                    const char *connected = JsonGet(q, "isConnected");
                    if (!connected)
                        connected = JsonGet(q, "is_connected");
                    if (MonitorPlayerFilter::IncludeNode(connected != nullptr, connected)) {
                        char nm[MONITOR_PLAYER_LEN] = {};
                        if (JsonGetStrAny(q, "playerName", "player_name", nm, sizeof(nm)) ||
                            JsonGetStr(q, "name", nm, sizeof(nm))) {
                            bool dup = false;
                            for (u8 i = 0; i < r.playerN; i++) {
                                if (strcmp(r.player[i], nm) == 0) {
                                    dup = true;
                                    break;
                                }
                            }
                            if (nm[0] && !dup)
                                snprintf(r.player[r.playerN++], MONITOR_PLAYER_LEN, "%s", nm);
                        }
                    }
                } else if (*q == '"') {
                    char nm[MONITOR_PLAYER_LEN] = {};
                    const char *s2 = q;
                    if (JsonString(&s2, nm, sizeof(nm)) && nm[0])
                        snprintf(r.player[r.playerN++], MONITOR_PLAYER_LEN, "%s", nm);
                }
                q = JsWs(next);
                if (*q == ',') q = JsWs(q + 1);
            }
        }
        /* 房主最前且不重复 */
        if (hostName[0]) {
            bool dup = false;
            for (u8 i = 0; i < r.playerN; i++) {
                if (strcmp(r.player[i], hostName) == 0) {
                    dup = true;
                    break;
                }
            }
            if (!dup && r.playerN < MONITOR_MAX_PLAYERS) {
                memmove(r.player[1], r.player[0], (size_t)r.playerN * MONITOR_PLAYER_LEN);
                snprintf(r.player[0], MONITOR_PLAYER_LEN, "%.31s", hostName);
                r.playerN++;
            }
        }
        /* The server's count is authoritative. A short-lived/stale nodes array
         * must not display more names than nodeCount says are connected. */
        if (hasPlayerCount && r.players > 0 && r.playerN > r.players) {
            const u8 keep = static_cast<u8>(r.players);
            for (u8 i = keep; i < r.playerN; i++)
                memset(r.player[i], 0, MONITOR_PLAYER_LEN);
            r.playerN = keep;
        }
        /* 人数兜底放到房主处理之后:房主若不在 nodes 里也计入人数 */
        if (r.players == 0)
            r.players = r.playerN ? r.playerN : 1;
        if (r.playersMax == 0)
            r.playersMax = r.players;
        if (r.game[0])
            qr->roomN++;

        const char *next = JsonSkip(p, 0);
        if (!next)
            break;
        next = JsWs(next);
        if (*next != ',')
            break;
        p = JsWs(next + 1);
    }
}

static bool QueryGraphqlRequest(const char *host, u16 port, const char *query,
                                QueryResult *qr, bool *retryLegacy, int timeoutMs = 4000) {
    if (retryLegacy)
        *retryLegacy = false;
    char url[160];
    snprintf(url, sizeof(url), "http://%s:%u/", host, (unsigned)port);
    std::string payload = "{\"query\":\"";
    payload += query;                    /* 查询串无引号/反斜杠,可直接拼接 */
    payload += "\"}";
    std::string resp;
    if (!HttpPostJson(url, payload.c_str(), &resp, timeoutMs, kMaxHttpBody)) {
        /* 仅当返回 HTTP 400/422 (错误码 = 100 + status,即 500/522) 时才可能是
         * 旧 GraphQL schema 字段校验报错;1.0 REST 服务器对 POST / 返回 HTTP 404/405
         * (504/505),此时必须立即回退到 GET /info,不能再连发 3 次 GraphQL 浪费时间。 */
        if (retryLegacy && (g_httpErr == 500 || g_httpErr == 522))
            *retryLegacy = true;
        return false;
    }

    /* GraphQL 通常以 HTTP 200 返回字段校验错误;网络超时/断连则直接
     * 交给 REST 回退,避免额外等待一个超时周期。 */
    const char *errors = JsonGet(resp.c_str(), "errors");
    if (errors && *errors == '[' && *JsWs(errors + 1) != ']') {
        if (retryLegacy)
            *retryLegacy = true;
        return false;
    }
    const char *data = JsonGet(resp.c_str(), "data");
    if (!data) {
        if (retryLegacy)
            *retryLegacy = true;
        return false;
    }
    u32 v = 0;
    const char *info = JsonGet(data, "serverInfo");
    if (!info || !JsonGetU32(info, "online", &v)) {
        if (retryLegacy)
            *retryLegacy = true;
        return false;
    }
    qr->online = (s32)v;
    const char *rooms = JsonGet(data, "room");
    if (rooms)
        ParseRoomArray(rooms, qr);
    return true;
}

static bool QueryGraphql(const char *host, u16 port, QueryResult *qr, int timeoutMs = 4000) {
    /* Prefer title data + connected-node flags. On schema validation errors,
     * progressively drop optional fields; transport errors still go straight
     * to REST rather than paying for another timeout. */
    bool retry = false;
    if (QueryGraphqlRequest(host, port, kGraphqlQuery, qr, &retry, timeoutMs))
        return true;
    if (!retry || IoAbort())
        return false;

    const char *fallback[] = { kGraphqlQueryNoAdvert,
                               kGraphqlQueryNoConnection,
                               kGraphqlQueryOldest };
    for (const char *query : fallback) {
        if (IoAbort())
            return false;
        bool retryNext = false;
        if (QueryGraphqlRequest(host, port, query, qr, &retryNext, timeoutMs))
            return true;
        if (!retryNext)
            return false;
    }
    return false;
}

static bool QueryRest(const char *host, u16 port, QueryResult *qr, int timeoutMs = 4000) {
    char url[160];
    snprintf(url, sizeof(url), "http://%s:%u/info", host, (unsigned)port);
    std::string resp;
    if (!HttpGet(url, &resp, timeoutMs, kMaxHttpBody))
        return false;
    const char *root = JsWs(SkipBom(resp.c_str()));
    u32 v = 0;
    if (JsonGetU32(root, "online", &v) || JsonGetU32(root, "clientCount", &v))
        qr->online = (s32)v;
    const char *rooms = JsonGet(root, "rooms");
    if (rooms)
        ParseRoomArray(rooms, qr);
    return qr->online >= 0;
}

/* ------------------------------------------------------------------ */
/* UDP 主动房间扫描(lan-play 中继协议的 LDN 扫描)                     */
/* ------------------------------------------------------------------ */

/* LanPlayMonitor 的 LDN_SCAN_FRAME 预生成常量:
 *   0x01                              lan-play 原始包 chunk
 *   IPv4(10.13.37.0 -> 10.13.255.255, UDP 11452)
 *   LDN 头 {00 14 45 11} + type=0     扫描请求
 * 校验和已预计算,勿手改。 */
static const u8 kScanFrame[] = {
    0x01, 0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x01,
    0xAC, 0x0A, 0x0D, 0x25, 0x00, 0x0A, 0x0D, 0xFF, 0xFF, 0x2C, 0xBC, 0x2C,
    0xBC, 0x00, 0x14, 0x28, 0x0F, 0x00, 0x14, 0x45, 0x11, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
};

/* ldn_mitm RLE 解压:字面字节;0x00 + count = count 个 0 */
static bool LdnDecompress(const u8 *in, size_t inLen, u8 *out, size_t expect) {
    if (expect == 0 || expect > 8192 || inLen > 8192)
        return false;
    size_t o = 0, i = 0;
    while (i < inLen && o < expect) {
        u8 v = in[i++];
        out[o++] = v;
        if (v == 0) {
            if (i >= inLen)
                return false;
            u8 rep = in[i++];
            if (o + rep > expect)
                return false;
            memset(out + o, 0, rep);
            o += rep;
        }
    }
    return i == inLen && o == expect;
}

/* NetworkInfo(≥0x480)-> 房间条目 + 会话标识(去重用) */
static bool ParseNetworkInfo(const u8 *p, size_t len, MonitorRoom *out,
                             char *sessionTag, size_t tagN) {
    if (len < 0x480)
        return false;
    memset(out, 0, sizeof(*out));
    char cid[20];
    for (int i = 0; i < 8; i++)
        snprintf(cid + i * 2, 3, "%02X", p[7 - i]);   /* 小端 8 字节 -> 标题ID */

    /* NetworkInfo: advertiseDataSize @ 0x26a, data @ 0x26c; the first
     * NodeInfo's playerName (host) starts at 0x74. */
    char advertiseHex[MonitorTitleResolver::kAdvertiseDataMaxHex + 1] = {};
    size_t advertiseSize = (size_t)p[0x26A] | ((size_t)p[0x26B] << 8);
    if (advertiseSize > MonitorTitleResolver::kAdvertiseDataMaxBytes)
        advertiseSize = MonitorTitleResolver::kAdvertiseDataMaxBytes;
    if (0x26C + advertiseSize > len)
        advertiseSize = 0;
    static const char kHex[] = "0123456789abcdef";
    for (size_t i = 0; i < advertiseSize; i++) {
        const u8 byte = p[0x26C + i];
        advertiseHex[i * 2] = kHex[byte >> 4];
        advertiseHex[i * 2 + 1] = kHex[byte & 0x0F];
    }
    char hostName[MONITOR_PLAYER_LEN + 1] = {};
    memcpy(hostName, p + 0x74, MONITOR_PLAYER_LEN);
    hostName[MONITOR_PLAYER_LEN] = 0;
    FormatGameName(cid, advertiseHex, hostName, out->game, sizeof(out->game));

    u32 maxN = p[0x66];
    u32 cnt = p[0x67];
    if (maxN > 8) maxN = 8;
    if (cnt > 8) cnt = 8;
    out->players = cnt;
    out->playersMax = maxN ? maxN : cnt;
    if (sessionTag && tagN > 0) {
        /* 与 lpm_main.py 一致:sessionId = payload[16:32] 的 hex;
           全零时退回标题ID 做标识。 */
        bool allZero = true;
        for (int i = 0; i < 16; i++) {
            if (p[16 + i]) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            snprintf(sessionTag, tagN, "%s", cid);
        } else {
            char tag[33];
            for (int i = 0; i < 16; i++)
                snprintf(tag + i * 2, 3, "%02x", p[16 + i]);
            snprintf(sessionTag, tagN, "%s", tag);
        }
        snprintf(out->sessionId, sizeof(out->sessionId), "%s", sessionTag);
    }
    /* 玩家名单:NetworkInfo 的 nodes[8] 带每个节点的用户名(起始 0x68、
     * 步长 0x40:isConnected @+11、userName[33] @+12)。只读取 nodeCount
     * 范围内的槽位;固定数组后面的槽可能保留上一个房间的旧昵称/连接位,
     * 是切换房间或服务器后偶发串名的来源。主机(AP, nodes[0])排最前。 */
    if (len >= 0x68 + (size_t)cnt * 0x40) {
        u8 pn = 0;
        for (u32 i = 0; i < cnt && pn < MONITOR_MAX_PLAYERS; i++) {
            const u8 *nd = p + 0x68 + (size_t)i * 0x40;
            if (!MonitorPlayerFilter::IncludeConnectedSlot(i, cnt, nd[11] == 1))
                continue;
            char nm[MONITOR_PLAYER_LEN];
            memcpy(nm, nd + 12, MONITOR_PLAYER_LEN - 1);
            nm[MONITOR_PLAYER_LEN - 1] = 0;
            if (nm[0]) {
                bool dup = false;
                for (u8 j = 0; j < pn; j++) {
                    if (strcmp(out->player[j], nm) == 0) {
                        dup = true;
                        break;
                    }
                }
                if (!dup)
                    snprintf(out->player[pn++], MONITOR_PLAYER_LEN, "%s", nm);
            }
        }
        out->playerN = pn;
    }
    return out->game[0] != 0;
}

/* IPv4 + UDP(11452) + LDN 响应 */
static bool ParseLdnResponse(const u8 *pkt, size_t len, MonitorRoom *room,
                             char *sessionTag, size_t tagN) {
    if (len < 20 || (pkt[0] >> 4) != 4)
        return false;
    size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl + 8)
        return false;
    if (pkt[9] != 17)                      /* UDP */
        return false;
    const u8 *udp = pkt + ihl;
    u32 sport = ((u32)udp[0] << 8) | udp[1];
    u32 dport = ((u32)udp[2] << 8) | udp[3];
    if (sport != 11452 || dport != 11452)
        return false;
    size_t udpLen = ((size_t)udp[4] << 8) | udp[5];
    if (udpLen < 8)
        return false;
    size_t body = udpLen - 8;
    if (body > len - ihl - 8)
        body = len - ihl - 8;
    const u8 *ldn = udp + 8;
    if (body < 12)
        return false;
    if (ldn[0] != 0x00 || ldn[1] != 0x14 || ldn[2] != 0x45 || ldn[3] != 0x11)
        return false;
    if (ldn[4] != 1)                       /* type 1 = NetworkInfo 响应 */
        return false;
    size_t bodyLen   = (size_t)ldn[6] | ((size_t)ldn[7] << 8);
    size_t decompLen = (size_t)ldn[8] | ((size_t)ldn[9] << 8);
    if (bodyLen > body - 12)
        return false;

    /* This parser is only called by the single monitor worker. Keep the
     * decompression scratch off its stack; older ovlloader builds provide a
     * smaller/less forgiving thread stack than current builds. */
    static u8 tmp[8192];
    const u8 *info = ldn + 12;
    size_t infoLen = bodyLen;
    if (ldn[5] == 1) {                     /* 压缩 */
        if (!LdnDecompress(info, bodyLen, tmp, decompLen))
            return false;
        info = tmp;
        infoLen = decompLen;
    }
    return ParseNetworkInfo(info, infoLen, room, sessionTag, tagN);
}

/* type=3 分片重组:同 src+ident 的分片按 pmtu 偏移拼接 */
struct FragSlot {
    bool used;
    u32 srcIp;
    u16 ident;
    u8  total;
    u16 pmtu;
    u16 dataLen;
    u64 partsMask;                  /* 已收分片位图(total ≤ 64) */
    u8  data[8192];
};
static FragSlot g_frags[16];

static bool FragAdd(const u8 *frame, size_t len, const u8 **outPkt, size_t *outLen) {
    if (len < 16)
        return false;
    u32 srcIp;
    memcpy(&srcIp, frame, 4);
    u16 ident = (u16)(((u32)frame[8] << 8) | frame[9]);
    u8 part = frame[10];
    u8 total = frame[11];
    u16 partLen = (u16)((u32)frame[12] | ((u32)frame[13] << 8));
    u16 pmtu = (u16)(((u32)frame[14] << 8) | frame[15]);
    if (total == 0 || total > 64 || part >= total || pmtu == 0)
        return false;
    if ((size_t)partLen > len - 16)
        return false;
    size_t end = (size_t)part * pmtu + partLen;
    if (end == 0 || end > 8192)
        return false;

    FragSlot *slot = nullptr;
    for (auto &f : g_frags) {
        if (f.used && f.srcIp == srcIp && f.ident == ident) {
            slot = &f;
            break;
        }
    }
    if (!slot) {
        for (auto &f : g_frags) {
            if (!f.used) {
                slot = &f;
                break;
            }
        }
        if (!slot)
            return false;
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        slot->srcIp = srcIp;
        slot->ident = ident;
        slot->total = total;
        slot->pmtu = pmtu;
    }
    if (slot->total != total || slot->pmtu != pmtu) {
        slot->used = false;
        return false;
    }
    memcpy(slot->data + (size_t)part * pmtu, frame + 16, partLen);
    if ((size_t)part * pmtu + partLen > slot->dataLen)
        slot->dataLen = (u16)end;
    slot->partsMask |= 1ull << part;

    u64 need = (total == 64) ? ~0ull : ((1ull << total) - 1);
    if (slot->partsMask != need)
        return false;
    *outPkt = slot->data;
    *outLen = slot->dataLen;
    slot->used = false;
    return true;
}

static void UdpRoomScan(const char *host, u16 port, QueryResult *qr,
                        int scanMs = 1000) {
    struct sockaddr_in sa;
    if (!HttpResolve(host, &sa))
        return;
    sa.sin_port = htons(port);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return;
    }

    /* 排空积压并保持非阻塞,配合 10ms select 随时响应返回键中止 */
    HttpSetNonBlock(fd, true);
    u8 drain[2048];
    while (recv(fd, drain, sizeof(drain), 0) > 0) {}

    memset(g_frags, 0, sizeof(g_frags));

    Deadline start = std::chrono::steady_clock::now();
    Deadline deadline = start + std::chrono::milliseconds(scanMs);
    Deadline nextSend = start;

    char seen[kMaxScanRooms][36];
    u32 seenN = 0;

    u8 frame[2048];
    while (std::chrono::steady_clock::now() < deadline && qr->roomN < MONITOR_MAX_ROOMS) {
        if (IoAbort()) {
            close(fd);
            return;
        }
        Deadline now = std::chrono::steady_clock::now();
        if (now >= nextSend) {
            send(fd, kScanFrame, sizeof(kScanFrame), 0);
            nextSend = now + std::chrono::milliseconds(350);
        }
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        struct timeval rtv;
        rtv.tv_sec = 0;
        rtv.tv_usec = 10 * 1000;
        int sel = select(fd + 1, &rset, nullptr, nullptr, &rtv);
        if (sel <= 0)
            continue;
        ssize_t n = recv(fd, frame, sizeof(frame), 0);
        if (n <= 0)
            continue;
        const u8 *pkt = nullptr;
        size_t pktLen = 0;
        if (frame[0] == 1) {
            pkt = frame + 1;
            pktLen = (size_t)n - 1;
        } else if (frame[0] == 3) {
            if (!FragAdd(frame + 1, (size_t)n - 1, &pkt, &pktLen))
                continue;
        } else {
            continue;
        }

        MonitorRoom room;
        memset(&room, 0, sizeof(room));
        char tag[36] = {};
        if (!ParseLdnResponse(pkt, pktLen, &room, tag, sizeof(tag)))
            continue;

        bool dup = false;
        for (u32 i = 0; i < seenN; i++) {
            if (strcmp(seen[i], tag) == 0) {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;
        if (seenN < kMaxScanRooms)
            snprintf(seen[seenN++], sizeof(seen[0]), "%s", tag);

        qr->rooms[qr->roomN++] = room;
    }
    close(fd);
}

/* ------------------------------------------------------------------ */
/* 房间过期缓存 (未扫到后保留 10 秒,彻底消除偶发丢包导致房间闪隐)       */
/* ------------------------------------------------------------------ */

/* 查询/UDP 扫描都有偶发丢包与瞬间空列表(日志里 scan rooms=0/1 交替),
 * 直接把当次结果写进快照会让房间列表一会儿消失一会儿出现。
 * 缓存以 sessionId 为键:
 *   - 命中即刷新 lastSeen 并清空 missingSince;
 *   - 某轮未扫到时先记录首次缺失时刻 missingSince,从缺失时刻起再保留 10 秒
 *     (kRoomExpireGrace = 10s),若期间重新扫到则无缝恢复,彻底消除偶发丢包闪退;
 *   - 切换服务器时清空。 */
static constexpr auto kRoomTtl         = std::chrono::seconds(12);
static constexpr auto kRoomExpireGrace = std::chrono::seconds(10);

struct RoomCacheEnt {
    bool used = false;
    bool seenInPoll = false;
    char key[40] = {};
    Deadline lastSeen{};
    Deadline missingSince{};
    MonitorRoom room;
};
static RoomCacheEnt g_roomCache[MONITOR_MAX_ROOMS];
static char g_cacheServer[128] = {};    /* 缓存归属的服务器 host:port */
static Deadline g_lastOk{};             /* 最近一次查询成功时刻 */
static bool  g_haveLastOk = false;
static s32   g_lastOnline = -1;
static s32   g_lastRoomCount = -1;

static void RoomCacheKey(const MonitorRoom &r, char *out, size_t n) {
    if (r.sessionId[0])
        snprintf(out, n, "%s", r.sessionId);
    else
        snprintf(out, n, "g:%s", r.game);
}

static void RoomCacheReset() {
    for (auto &e : g_roomCache) {
        e.used = false;
        e.seenInPoll = false;
        e.missingSince = Deadline{};
    }
    g_cacheServer[0] = 0;
    g_haveLastOk = false;
    g_lastOnline = -1;
    g_lastRoomCount = -1;
}

static void RoomCacheBeginPoll() {
    for (auto &e : g_roomCache) {
        if (e.used)
            e.seenInPoll = false;
    }
}

static void RoomCacheUpsert(const MonitorRoom &r, const Deadline &now) {
    char key[40];
    RoomCacheKey(r, key, sizeof(key));
    const bool hasHostAndGame = (r.game[0] != 0 && r.playerN > 0 && r.player[0][0] != 0);
    int freeSlot = -1, oldest = -1;
    for (u32 i = 0; i < MONITOR_MAX_ROOMS; i++) {
        RoomCacheEnt &e = g_roomCache[i];
        if (!e.used) {
            if (freeSlot < 0)
                freeSlot = (int)i;
            continue;
        }
        const bool sameSession = (strcmp(e.key, key) == 0);
        const bool sameHostGame = (hasHostAndGame &&
                                   strcmp(e.room.game, r.game) == 0 &&
                                   e.room.playerN > 0 &&
                                   strcmp(e.room.player[0], r.player[0]) == 0);
        if (sameSession || sameHostGame) {
            snprintf(e.key, sizeof(e.key), "%s", key);
            e.room = r;
            e.lastSeen = now;
            e.missingSince = Deadline{};
            e.seenInPoll = true;
            return;
        }
        if (oldest < 0 || e.lastSeen < g_roomCache[oldest].lastSeen)
            oldest = (int)i;
    }
    int slot = (freeSlot >= 0) ? freeSlot : oldest;
    if (slot < 0)
        return;
    RoomCacheEnt &e = g_roomCache[slot];
    e.used = true;
    e.seenInPoll = true;
    snprintf(e.key, sizeof(e.key), "%s", key);
    e.lastSeen = now;
    e.missingSince = Deadline{};
    e.room = r;
}

static void RoomCacheExpire(const Deadline &now, bool pollCompletedOk) {
    for (auto &e : g_roomCache) {
        if (!e.used)
            continue;
        if (!pollCompletedOk) {
            if ((now - e.lastSeen) > kRoomTtl)
                e.used = false;
            continue;
        }
        if (e.seenInPoll)
            continue;
        if (e.missingSince.time_since_epoch().count() == 0) {
            /* 首次未扫到:开始 3 秒过期倒计时,本轮继续保留显示 */
            e.missingSince = now;
            continue;
        }
        if ((now - e.missingSince) >= kRoomExpireGrace)
            e.used = false;
    }
}

/* ------------------------------------------------------------------ */
/* 刷新流程                                                            */
/* ------------------------------------------------------------------ */

/* TLS/curl and JSON parsing can nest more deeply on older runtimes. Reserve
 * 256 KiB instead of 64 KiB; this is static overlay memory, not heap. */
alignas(0x1000) static u8 g_workerStack[0x40000];

static void LogWorkerStack(const char *phase) {
    volatile u8 probe = 0;
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(g_workerStack);
    const std::uintptr_t end = base + sizeof(g_workerStack);
    const std::uintptr_t current = reinterpret_cast<std::uintptr_t>(&probe);
    char msg[128];
    if (current >= base && current < end) {
        snprintf(msg, sizeof(msg), "%s worker-stack used=%uK free=%uK", phase,
                 static_cast<unsigned>((end - current) / 1024),
                 static_cast<unsigned>((current - base) / 1024));
    } else {
        /* Never print a wrapped/negative "free stack" number. This also
         * diagnoses a runtime that did not use the supplied stack buffer. */
        snprintf(msg, sizeof(msg), "%s worker-stack range-mismatch sp=%p range=%p..%p",
                 phase, reinterpret_cast<void *>(current),
                 reinterpret_cast<void *>(base), reinterpret_cast<void *>(end));
    }
    MonLog(msg);
}

static bool g_titleLoaded = false;

enum ServerProto : u8 {
    ProtoUnknown = 0,
    ProtoGraphql = 1,
    ProtoRest    = 2,
};

static u8 DefaultProtoForHostPort(const char *host, u16 port) {
    if (!host || !host[0])
        return ProtoUnknown;
    if (strcasecmp(host, "olunira.fun") == 0 ||
        strcasecmp(host, "switch.r3ps4j.nl") == 0 ||
        strcasecmp(host, "muitxobem-lanplay.ddns.net") == 0)
        return ProtoRest;
    if (strcasecmp(host, "switch.jayseateam.nl") == 0 && port == 11453)
        return ProtoRest;
    return ProtoUnknown;
}

static u8 StatsGetProtoByAddr(const char *host, u16 port);
static u8 StatsGetProtoByAddr(const char *host, u16 port);
static void StatsSetProtoByAddr(const char *host, u16 port, u8 proto);
static s32 StatsGetLatencyByAddr(const char *host, u16 port);
static void StatsStoreByAddr(const char *host, u16 port, s32 online, s32 rooms, s32 latencyMs);
static s32 ProbeLatencyMs(const char *host, u16 port);
static void StatsBuildTableIfNeeded(bool force = false);
static bool ResolveSelectedFromStats(const char *wantName,
                                     char *nameOut, size_t nameN,
                                     char *hostOut, size_t hostN, u16 *portOut);
static void RefreshAllServersBatch(const char *selHost, u16 selPort,
                                   QueryResult *selQr, bool *selOkOut,
                                   s32 *selLatOut, int *selHttpErrOut);
static void StatsCommitBatchLocked(const char *selHost, u16 selPort,
                                   s32 selOnline, s32 selRooms, s32 selLat);

/* 按协议类型(含缓存提示与自动回退)查询服务器在线人数与房间列表,
 * 同时带出本次 HTTP 往返折算的单程 RTT(供未开启 UDP PING 回显的服务器兜底延迟)。 */
static bool QueryAuto(const char *host, u16 port, QueryResult *qr,
                      int timeoutMs, s32 *httpRttOut) {
    if (httpRttOut)
        *httpRttOut = 0;
    g_httpRttMs = 0;

    u8 hint = StatsGetProtoByAddr(host, port);
    if (hint == ProtoUnknown)
        hint = DefaultProtoForHostPort(host, port);

    bool ok = false;
    u8 usedProto = ProtoUnknown;
    if (hint == ProtoRest) {
        ok = QueryRest(host, port, qr, timeoutMs);
        if (ok) {
            usedProto = ProtoRest;
        } else if (!IoAbort()) {
            ok = QueryGraphql(host, port, qr, timeoutMs);
            if (ok)
                usedProto = ProtoGraphql;
        }
    } else {
        ok = QueryGraphql(host, port, qr, timeoutMs);
        if (ok) {
            usedProto = ProtoGraphql;
        } else if (!IoAbort()) {
            ok = QueryRest(host, port, qr, timeoutMs);
            if (ok)
                usedProto = ProtoRest;
        }
    }
    if (ok) {
        if (httpRttOut && g_httpRttMs > 0)
            *httpRttOut = g_httpRttMs;
        if (usedProto != ProtoUnknown)
            StatsSetProtoByAddr(host, port, usedProto);
    }
    return ok;
}

static void DoRefresh(const char *nameOverride, bool reloadSubs,
                      MonitorTargetGeneration::Value targetGen) {
    bool staleTarget = false;
    {
        std::scoped_lock lk(g_mutex);
        staleTarget = !g_targetGen.IsCurrent(targetGen);
        if (!staleTarget) {
            g_snap.busy = true;
            /* 同一服务器的轮询继续展示上一结果;切服时由请求入口先清空。 */
            snprintf(g_snap.status, sizeof(g_snap.status), "%s",
                     T_STR("正在查询…", "正在查詢…"));
        }
    }
    if (staleTarget) {
        MonLog("refresh-discard stale-target-before-start");
        return;
    }
    if (IoAbort())
        return;

    LogWorkerStack("refresh-start");
    EnsureSockets();
    StatsBuildTableIfNeeded(false);

    static QueryResult qr;            /* 约 8.7KB:static,不占工作线程栈 */
    qr = QueryResult{};

    /* 1. 当前选择的服务器:优先从内存统计表匹配(由 UI 从 sysmodule 同步),再读 relay.cfg */
    char name[48] = {}, host[64] = {};
    u16 port = 11451;
    bool haveServer = ResolveSelectedFromStats(nameOverride, name, sizeof(name),
                                               host, sizeof(host), &port);
    if (!haveServer) {
        haveServer = ResolveSelectedServer(nameOverride, name, sizeof(name),
                                           host, sizeof(host), &port);
    }
    {
        char m[160];
        if (haveServer)
            snprintf(m, sizeof(m), "resolve ok gen=%u %s %s:%u",
                     static_cast<unsigned>(targetGen), name, host, (unsigned)port);
        else
            snprintf(m, sizeof(m), "resolve FAIL gen=%u %s",
                     static_cast<unsigned>(targetGen),
                     nameOverride ? nameOverride : "(selected)");
        MonLog(m);
    }

    /* Publish/clear only if this request still targets the selected server. */
    {
        char ident[128];
        snprintf(ident, sizeof(ident), "%s:%u", host, (unsigned)port);
        std::scoped_lock lk(g_mutex);
        staleTarget = !g_targetGen.IsCurrent(targetGen);
        if (!staleTarget) {
            snprintf(g_snap.server, sizeof(g_snap.server), "%.47s",
                     name[0] ? name : (host[0] ? host : "?"));
            if (strcmp(ident, g_cacheServer) != 0) {
                RoomCacheReset();
                g_snap.online = -1;
                g_snap.roomCount = -1;
                g_snap.roomN = 0;
                memset(g_snap.rooms, 0, sizeof(g_snap.rooms));
                g_snap.version++;
            }
            snprintf(g_cacheServer, sizeof(g_cacheServer), "%s", ident);
        }
    }
    if (staleTarget) {
        MonLog("refresh-discard stale-target-after-resolve");
        return;
    }

    /* 2. 订阅(chinese_db.json):优先直接加载本地预置缓存,秒开查询房间;
     *    仅当本地缓存不存在或为空时才走 HTTPS 镜像(https://v6.gh-proxy.org/)
     *    下载补齐,彻底避免每次点开插件在寻找房间前卡在 curl TLS 握手与
     *    3MB 下载里导致按返回键迟迟弹不出特斯拉菜单。 */
    if ((reloadSubs || !g_titleLoaded) && !IoAbort()) {
        if (!g_titleLoaded) {
            EnsureTitleTables();
            if (g_titleKey) {
                g_titleArenaUsed = 0;
                memset(g_titleKey, 0, kTitleHashSize * sizeof(u64));
                if (ParseChineseDbFile(kSaveChinesePath) && g_titleArenaUsed > 0) {
                    g_titleLoaded = true;
                    MonLog("chinese: use cache");
                }
            }
        }
        if (!g_titleLoaded && !IoAbort()) {
            MonLog("subs-start");
            std::string chineseJson;
            if (DownloadSubscription(kSubChinesePath, &chineseJson) && !IoAbort()) {
                SaveFile(kSaveChinesePath, chineseJson);
                EnsureTitleTables();
                if (g_titleKey) {
                    g_titleArenaUsed = 0;
                    memset(g_titleKey, 0, kTitleHashSize * sizeof(u64));
                    std::string().swap(chineseJson);
                    if (ParseChineseDbFile(kSaveChinesePath) && g_titleArenaUsed > 0)
                        g_titleLoaded = true;
                    else
                        MonLog("chinese_db: open file failed");
                }
            } else {
                MonLog("chinese: no cache");
            }
        }
    }

    if (IoAbort()) {
        MonLog("refresh-discard aborted");
        return;
    }

    if (!haveServer) {
        bool stale = false;
        {
            std::scoped_lock lk(g_mutex);
            stale = !g_targetGen.IsCurrent(targetGen);
            if (!stale) {
                snprintf(g_snap.status, sizeof(g_snap.status), "%s",
                         T_STR("找不到选中的服务器", "找不到選中的伺服器"));
                g_snap.busy = false;
                g_snap.version++;
            }
        }
        if (stale)
            MonLog("refresh-discard stale-target-no-server");
        return;
    }

    if (!g_targetGen.IsCurrent(targetGen)) {
        MonLog("refresh-discard stale-target-before-query");
        return;
    }

    /* 4. 同步批量探测:在同一次刷新周期内并行探测当前选中的服务器以及列表中的
     *    全部其它服务器(共享 UDP DNS + 共享 UDP PING + 4 路非阻塞 HTTP 滑动窗口
     *    + 并行 UDP 房间扫描),并在同一把锁内同步提交 g_stats 与 g_snap,确保所有
     *    服务器的在线、房间、延迟与选中服务器在同一帧同步刷新。 */
    bool ok = false;
    s32 selLat = 0;
    int selHttpErr = 0;
    RefreshAllServersBatch(host, port, &qr, &ok, &selLat, &selHttpErr);
    if (IoAbort()) {
        MonLog("refresh-discard aborted");
        return;
    }
    {
        char m[64];
        snprintf(m, sizeof(m), "batch query e=%d on=%d rooms=%u lat=%d",
                 selHttpErr, qr.online, (unsigned)qr.roomN, (int)selLat);
        MonLog(m);
    }

    /* 7. 并入房间 5 秒 TTL 缓存后与全部服务器的统计表同步写快照:
     *    在同一把 g_mutex 锁内同时更新 g_stats[] 与 g_snap(version++),
     *    UI 在下一帧同时刷新游戏房间与所有中继服务器行的在线/房间/延迟。 */
    u32 mlogN = 0;
    s32 mlogOn = -1;
    bool staleAfterQuery = false;
    {
        const Deadline now = std::chrono::steady_clock::now();
        std::scoped_lock lk(g_mutex);
        staleAfterQuery = !g_targetGen.IsCurrent(targetGen);
        if (!staleAfterQuery) {
            if (ok) {
                RoomCacheBeginPoll();
                for (u32 i = 0; i < qr.roomN; i++)
                    RoomCacheUpsert(qr.rooms[i], now);
                g_lastOk = now;
                g_haveLastOk = true;
            }
            RoomCacheExpire(now, ok);

            u32 n = 0;
            s32 udpOnline = 0;
            for (u32 i = 0; i < MONITOR_MAX_ROOMS; i++) {
                if (g_roomCache[i].used) {
                    const MonitorRoom &rm = g_roomCache[i].room;
                    g_snap.rooms[n++] = rm;
                    udpOnline += (rm.players > 0) ? (s32)rm.players : 1;
                }
            }
            g_snap.roomN = n;
            const bool fresh = g_haveLastOk && (now - g_lastOk) <= kRoomTtl;
            if (ok) {
                s32 on = qr.online >= udpOnline ? qr.online : udpOnline;
                g_snap.online = on;
                g_snap.roomCount = (s32)n;
                g_lastOnline = on;
                g_lastRoomCount = (s32)n;
            } else if (fresh) {
                /* 瞬间失败:沿用最近一次成功的在线/房间数 */
                g_snap.online = g_lastOnline;
                g_snap.roomCount = (s32)n;
                g_lastRoomCount = (s32)n;
            } else {
                g_snap.online = -1;
                g_snap.roomCount = -1;
            }
            if (!ok && !fresh) {
                if (!g_sockInited)
                    snprintf(g_snap.status, sizeof(g_snap.status), "%s",
                             T_STR("网络初始化失败", "網絡初始化失敗"));
                else
                    snprintf(g_snap.status, sizeof(g_snap.status), "%s e=%d",
                             T_STR("查询失败", "查詢失敗"), selHttpErr);
            } else if (n == 0) {
                snprintf(g_snap.status, sizeof(g_snap.status), "%s",
                         T_STR("暂无房间", "暫無房間"));
            } else {
                g_snap.status[0] = 0;
            }
            /* 在同一把锁里同步提交所有服务器的在线/房间/延迟统计与选中服快照 */
            StatsCommitBatchLocked(host, port, g_snap.online, g_snap.roomCount, selLat);
            g_snap.busy = false;
            g_snap.version++;
            mlogN = n;
            mlogOn = g_snap.online;
        }
    }
    if (staleAfterQuery) {
        MonLog("refresh-discard stale-target-after-query");
        return;
    }
    {
        char m[48];
        snprintf(m, sizeof(m), "cache rooms=%u on=%d", (unsigned)mlogN, (int)mlogOn);
        MonLog(m);
    }
}

/* ------------------------------------------------------------------ */
/* 每台服务器各自的在线 / 房间 / 延迟 (同步批量探测引擎)                 */
/* ------------------------------------------------------------------ */

static constexpr u32  kStatMaxServers    = MONITOR_MAX_SERVERS;
static constexpr int  kBatchHttpSlots    = 6;
static constexpr int  kBatchHttpMs       = 1200;
static constexpr int  kBatchScanMs       = 850;
static constexpr u64  kStatKeepOnFailMs  = 10000;
static constexpr u64  kRoomExpireGraceMs = 10000;

struct ServerStat {
    char name[32];
    char addr[64];
    s32  online;        /* -1 = 未知 */
    s32  rooms;         /* -1 = 未知 */
    s32  latencyMs;     /* 0 = 未知 */
    u64  stampMs;       /* 上次测量时刻;0 = 从未测过 */
    u64  lastScanMs;    /* 上次向该服发送 UDP kScanFrame 的时刻(用于扣除自身扫描器占用的 1 个在线名额) */
    u64  roomMissingSinceMs; /* 房间首次未扫到的时刻;保留 10 秒过期缓存防闪烁 */
    u8   proto;         /* ServerProto: 缓存 graphql/rest 类型 */
    u8   failCount;     /* 连续失败次数 */
};

static ServerStat g_stats[kStatMaxServers];
static u32 g_statCount = 0;
static char g_statCfgKey[64];        /* 服务器列表指纹,仅在条目增删改时更新表 */
static int g_scanUdpFd = -1;         /* 持久化复用同一个 UDP 扫描端口,避免每次扫描在服务端新增临时客户端 */
static int g_selScanUdpFd = -1;      /* 选中服务器专用持久 connect() UDP 扫描端口 */
static struct sockaddr_in g_selScanSa = {};

static u64 MonNowMs() {
    return (u64)std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
               .count() + 1ull;
}

static void SplitAddrHostPort(const char *addrIn, char *hostOut, size_t hostN, u16 *portOut) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", addrIn ? addrIn : "");
    u16 port = 11451;
    char *colon = strrchr(buf, ':');
    if (colon) {
        *colon = 0;
        int p = atoi(colon + 1);
        if (p > 0 && p <= 65535)
            port = (u16)p;
    }
    snprintf(hostOut, hostN, "%s", buf);
    if (portOut)
        *portOut = port;
}

static void StatsApplyFreshListLocked(ServerStat *fresh, u32 n) {
    for (u32 k = 0; k < n; k++) {
        for (u32 oldIdx = 0; oldIdx < g_statCount; oldIdx++) {
            if (strcmp(fresh[k].addr, g_stats[oldIdx].addr) == 0) {
                fresh[k].online = g_stats[oldIdx].online;
                fresh[k].rooms = g_stats[oldIdx].rooms;
                fresh[k].latencyMs = g_stats[oldIdx].latencyMs;
                fresh[k].stampMs = g_stats[oldIdx].stampMs;
                fresh[k].lastScanMs = g_stats[oldIdx].lastScanMs;
                fresh[k].roomMissingSinceMs = g_stats[oldIdx].roomMissingSinceMs;
                if (g_stats[oldIdx].proto != ProtoUnknown)
                    fresh[k].proto = g_stats[oldIdx].proto;
                fresh[k].failCount = g_stats[oldIdx].failCount;
                break;
            }
        }
    }
    memcpy(g_stats, fresh, sizeof(ServerStat) * kStatMaxServers);
    g_statCount = n;
}

void MonitorSetServerList(const MonitorServer *servers, u32 count) {
    if (!servers && count > 0)
        return;
    if (count > kStatMaxServers)
        count = kStatMaxServers;
    ServerStat fresh[kStatMaxServers] = {};
    u32 hash = 2166136261u;
    for (u32 i = 0; i < count; i++) {
        char host[64] = {};
        u16 port = 11451;
        SplitAddrHostPort(servers[i].addr, host, sizeof(host), &port);
        snprintf(fresh[i].name, sizeof(fresh[i].name), "%.31s", servers[i].name);
        snprintf(fresh[i].addr, sizeof(fresh[i].addr), "%.55s:%u", host, (unsigned)port);
        fresh[i].online = -1;
        fresh[i].rooms = -1;
        fresh[i].proto = DefaultProtoForHostPort(host, port);
        for (const char *p = fresh[i].addr; *p; p++)
            hash = (hash ^ (u8)*p) * 16777619u;
    }
    char key[64];
    snprintf(key, sizeof(key), "%u:%08x", (unsigned)count, (unsigned)hash);
    std::scoped_lock lk(g_mutex);
    snprintf(g_statCfgKey, sizeof(g_statCfgKey), "%s", key);
    StatsApplyFreshListLocked(fresh, count);
}

static bool ResolveSelectedFromStats(const char *wantName,
                                     char *nameOut, size_t nameN,
                                     char *hostOut, size_t hostN, u16 *portOut) {
    if (!wantName || !wantName[0])
        return false;
    char want[48];
    snprintf(want, sizeof(want), "%s", wantName);
    size_t wl = strlen(want);
    while (wl > 0 && (want[wl - 1] == ' ' || want[wl - 1] == '\t'))
        want[--wl] = 0;
    if (!want[0])
        return false;
    std::scoped_lock lk(g_mutex);
    for (u32 i = 0; i < g_statCount; i++) {
        if (strcmp(g_stats[i].name, want) == 0) {
            snprintf(nameOut, nameN, "%s", g_stats[i].name);
            SplitAddrHostPort(g_stats[i].addr, hostOut, hostN, portOut);
            return hostOut[0] != 0;
        }
    }
    return false;
}

static u64 g_statCfgCheckedMs = 0;

static void StatsBuildTableIfNeeded(bool force) {
    if (IoAbort())
        return;
    {
        std::scoped_lock lk(g_mutex);
        if (!force && g_statCount > 0)
            return;
    }
    const u64 nowMs = MonNowMs();
    if (!force && g_statCfgCheckedMs != 0 && nowMs - g_statCfgCheckedMs < 3000)
        return;
    g_statCfgCheckedMs = nowMs;
    std::string cfg;
    if (!LoadFile(kRelayCfgPath, &cfg))
        return;

    ServerStat fresh[kStatMaxServers] = {};
    u32 n = 0;
    u32 hash = 2166136261u;
    size_t i = 0;
    while (i < cfg.size() && n < kStatMaxServers) {
        size_t e = cfg.find_first_of("\r\n", i);
        std::string line = cfg.substr(i, e == std::string::npos ? std::string::npos : e - i);
        i = (e == std::string::npos) ? cfg.size() : e + 1;
        char name[32] = {}, host[64] = {};
        u16 port = 0;
        if (!RelayParseLine(line.c_str(), name, sizeof(name), host, sizeof(host), &port))
            continue;
        snprintf(fresh[n].name, sizeof(fresh[n].name), "%s", name);
        snprintf(fresh[n].addr, sizeof(fresh[n].addr), "%.55s:%u", host, (unsigned)port);
        fresh[n].online = -1;
        fresh[n].rooms = -1;
        fresh[n].proto = DefaultProtoForHostPort(host, port);
        for (const char *p = fresh[n].addr; *p; p++)
            hash = (hash ^ (u8)*p) * 16777619u;
        n++;
    }
    char key[64];
    snprintf(key, sizeof(key), "%u:%08x", (unsigned)n, (unsigned)hash);
    if (strcmp(key, g_statCfgKey) == 0)
        return;
    snprintf(g_statCfgKey, sizeof(g_statCfgKey), "%s", key);

    {
        std::scoped_lock lk(g_mutex);
        StatsApplyFreshListLocked(fresh, n);
    }
    char m[48];
    snprintf(m, sizeof(m), "stats table n=%u", (unsigned)n);
    MonLog(m);
}

static u8 StatsGetProtoByAddr(const char *host, u16 port) {
    char addr[64];
    snprintf(addr, sizeof(addr), "%.55s:%u", host, (unsigned)port);
    std::scoped_lock lk(g_mutex);
    for (u32 i = 0; i < g_statCount; i++) {
        if (strcmp(g_stats[i].addr, addr) == 0)
            return g_stats[i].proto;
    }
    return ProtoUnknown;
}

static void StatsSetProtoByAddr(const char *host, u16 port, u8 proto) {
    char addr[64];
    snprintf(addr, sizeof(addr), "%.55s:%u", host, (unsigned)port);
    std::scoped_lock lk(g_mutex);
    for (u32 i = 0; i < g_statCount; i++) {
        if (strcmp(g_stats[i].addr, addr) == 0) {
            g_stats[i].proto = proto;
            break;
        }
    }
}

static s32 StatsGetLatencyByAddr(const char *host, u16 port) {
    char addr[64];
    snprintf(addr, sizeof(addr), "%.55s:%u", host, (unsigned)port);
    std::scoped_lock lk(g_mutex);
    for (u32 i = 0; i < g_statCount; i++) {
        if (strcmp(g_stats[i].addr, addr) == 0)
            return g_stats[i].latencyMs;
    }
    return 0;
}

static void StatsStoreByAddr(const char *host, u16 port, s32 online, s32 rooms, s32 latencyMs) {
    char addr[64];
    snprintf(addr, sizeof(addr), "%.55s:%u", host, (unsigned)port);
    const u64 nowMs = MonNowMs();
    std::scoped_lock lk(g_mutex);
    for (u32 i = 0; i < g_statCount; i++) {
        if (strcmp(g_stats[i].addr, addr) == 0) {
            g_stats[i].failCount = 0;
            if (online >= 0)
                g_stats[i].online = online;
            if (rooms >= 0)
                g_stats[i].rooms = rooms;
            if (latencyMs > 0)
                g_stats[i].latencyMs = latencyMs;
            g_stats[i].stampMs = nowMs;
            break;
        }
    }
}

struct BatchServerItem {
    char addr[64];
    char host[64];
    u16  port;
    u8   proto;
    bool resolved;
    bool hadRecentScan;
    bool didScan;
    struct sockaddr_in sa;
    s32  latMs;
    s32  httpRttMs;
    s32  rawOnline;
    s32  online;
    s32  rooms;
    s32  prevRooms;
    bool httpOk;
    int  httpErr;
};

static BatchServerItem g_batch[kStatMaxServers];
static u32 g_batchCount = 0;

/* 并行 DNS 解析:已命中缓存或 IP 字面量的 0ms 直接填充;其余未缓存域名通过单个
 * 非阻塞 UDP 套接字并发向 DNS 服务器查询(以 txid1=索引区分应答),一次性解析全部服务器。 */
static void BatchResolveAll(BatchServerItem *items, u32 count) {
    DnsInitServers();
    u32 unresolved = 0;
    for (u32 i = 0; i < count; i++) {
        memset(&items[i].sa, 0, sizeof(items[i].sa));
        items[i].sa.sin_family = AF_INET;
        items[i].sa.sin_port = htons(items[i].port);
        items[i].resolved = false;

        in_addr_t lit = inet_addr(items[i].host);
        if (lit != INADDR_NONE) {
            items[i].sa.sin_addr.s_addr = lit;
            items[i].resolved = true;
            continue;
        }
        for (int c = 0; c < g_dnsCacheN; c++) {
            if (strcasecmp(g_dnsCache[c].host, items[i].host) == 0 && g_dnsCache[c].ip != 0) {
                items[i].sa.sin_addr.s_addr = htonl(g_dnsCache[c].ip);
                items[i].resolved = true;
                break;
            }
        }
        if (!items[i].resolved)
            unresolved++;
    }
    if (unresolved == 0 || IoAbort())
        return;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        HttpSetNonBlock(fd, true);
        for (int s = 0; s < g_dnsSrvN && unresolved > 0 && !IoAbort(); s += 2) {
            for (u32 i = 0; i < count; i++) {
                if (items[i].resolved)
                    continue;
                u8 q[300];
                size_t qlen = DnsBuildQuery(items[i].host, q, sizeof(q), 0xA5, (u8)i);
                if (qlen == 0)
                    continue;
                for (int k = s; k < s + 2 && k < g_dnsSrvN; k++) {
                    struct sockaddr_in dsa;
                    memset(&dsa, 0, sizeof(dsa));
                    dsa.sin_family = AF_INET;
                    dsa.sin_port = htons(53);
                    dsa.sin_addr.s_addr = htonl(g_dnsSrv[k]);
                    sendto(fd, q, (int)qlen, 0, (struct sockaddr *)&dsa, sizeof(dsa));
                }
            }
            Deadline waitEnd = std::chrono::steady_clock::now() + std::chrono::milliseconds(420);
            while (std::chrono::steady_clock::now() < waitEnd && unresolved > 0 && !IoAbort()) {
                fd_set rset;
                FD_ZERO(&rset);
                FD_SET(fd, &rset);
                struct timeval tv = { 0, 10 * 1000 };
                int sel = select(fd + 1, &rset, nullptr, nullptr, &tv);
                if (sel <= 0)
                    continue;
                u8 r[512];
                for (;;) {
                    ssize_t n = recv(fd, r, sizeof(r), 0);
                    if (n <= 0)
                        break;
                    if (n >= 12 && r[0] == 0xA5) {
                        u32 idx = r[1];
                        u32 netIp = 0;
                        if (idx < count && !items[idx].resolved &&
                            DnsParseA(r, n, 0xA5, (u8)idx, &netIp) && netIp != 0) {
                            u32 hostIp = ntohl(netIp);
                            if (g_dnsCacheN < (int)(sizeof(g_dnsCache) / sizeof(g_dnsCache[0]))) {
                                snprintf(g_dnsCache[g_dnsCacheN].host,
                                         sizeof(g_dnsCache[0].host), "%s", items[idx].host);
                                g_dnsCache[g_dnsCacheN].ip = hostIp;
                                g_dnsCacheN++;
                            }
                            /* 相同域名的其它端口条目一并标记解析完成 */
                            for (u32 j = 0; j < count; j++) {
                                if (!items[j].resolved &&
                                    strcasecmp(items[j].host, items[idx].host) == 0) {
                                    items[j].sa.sin_addr.s_addr = netIp;
                                    items[j].resolved = true;
                                    if (unresolved > 0)
                                        unresolved--;
                                }
                            }
                        }
                    }
                }
            }
        }
        close(fd);
    }

    for (u32 i = 0; i < count && !IoAbort(); i++) {
        if (!items[i].resolved) {
            if (HttpResolve(items[i].host, &items[i].sa)) {
                items[i].sa.sin_port = htons(items[i].port);
                items[i].resolved = true;
            }
        }
    }
}

static bool ParseBatchHttpResponse(std::string &raw, bool restMode,
                                   QueryResult *qrOut, bool *retrySchemaOut,
                                   int *errOut) {
    if (retrySchemaOut)
        *retrySchemaOut = false;
    *qrOut = QueryResult{};

    int status = 0;
    std::string body;
    if (!HttpParseResponse(raw, &status, &body)) {
        if (errOut) *errOut = 7;
        return false;
    }
    if (status < 200 || status >= 300) {
        if (errOut) *errOut = 100 + status;
        if (!restMode && retrySchemaOut && (status == 400 || status == 422))
            *retrySchemaOut = true;
        return false;
    }

    if (restMode) {
        const char *root = JsWs(SkipBom(body.c_str()));
        u32 v = 0;
        if (JsonGetU32(root, "online", &v) || JsonGetU32(root, "clientCount", &v))
            qrOut->online = (s32)v;
        const char *rooms = JsonGet(root, "rooms");
        if (rooms)
            ParseRoomArray(rooms, qrOut);
        if (qrOut->online >= 0) {
            if (errOut) *errOut = 0;
            return true;
        }
        if (errOut) *errOut = 8;
        return false;
    }

    const char *errors = JsonGet(body.c_str(), "errors");
    if (errors && *errors == '[' && *JsWs(errors + 1) != ']') {
        if (retrySchemaOut) *retrySchemaOut = true;
        if (errOut) *errOut = 9;
        return false;
    }
    const char *data = JsonGet(body.c_str(), "data");
    if (!data) {
        if (retrySchemaOut) *retrySchemaOut = true;
        if (errOut) *errOut = 9;
        return false;
    }
    u32 v = 0;
    const char *info = JsonGet(data, "serverInfo");
    if (!info || !JsonGetU32(info, "online", &v)) {
        if (retrySchemaOut) *retrySchemaOut = true;
        if (errOut) *errOut = 9;
        return false;
    }
    qrOut->online = (s32)v;
    const char *rooms = JsonGet(data, "room");
    if (rooms)
        ParseRoomArray(rooms, qrOut);
    if (errOut) *errOut = 0;
    return true;
}

/* 并行 UDP 房间扫描:
 *   - 选中服务器(selIdx)使用独立持久 connect() 的 UDP 套接字(g_selScanUdpFd,
 *     send/recv),避免与其它服务器共用缓冲区或受 recvfrom 源地址过滤影响;
 *   - 其余服务器复用持久非阻塞 UDP 套接字(g_scanUdpFd);
 *   - 在 850ms 窗口内发 3 轮探测包(0ms / 280ms / 560ms),降低偶发丢包率。 */
static void BatchUdpRoomScan(BatchServerItem *items, const u32 *scanIdxs, u32 scanN,
                             s32 selIdx, QueryResult *selQr) {
    if (scanN == 0 || IoAbort())
        return;

    s32 selScanSlot = -1;
    for (u32 s = 0; s < scanN; s++) {
        if ((s32)scanIdxs[s] == selIdx) {
            selScanSlot = (s32)s;
            break;
        }
    }

    int selFd = -1;
    if (selScanSlot >= 0 && selIdx >= 0) {
        const struct sockaddr_in &targetSa = items[selIdx].sa;
        if (g_selScanUdpFd >= 0 &&
            (g_selScanSa.sin_addr.s_addr != targetSa.sin_addr.s_addr ||
             g_selScanSa.sin_port != targetSa.sin_port)) {
            close(g_selScanUdpFd);
            g_selScanUdpFd = -1;
        }
        if (g_selScanUdpFd < 0) {
            g_selScanUdpFd = socket(AF_INET, SOCK_DGRAM, 0);
            if (g_selScanUdpFd >= 0) {
                if (connect(g_selScanUdpFd, (const struct sockaddr *)&targetSa, sizeof(targetSa)) != 0) {
                    close(g_selScanUdpFd);
                    g_selScanUdpFd = -1;
                } else {
                    HttpSetNonBlock(g_selScanUdpFd, true);
                    g_selScanSa = targetSa;
                }
            }
        }
        selFd = g_selScanUdpFd;
        if (selFd >= 0) {
            u8 drain[1024];
            while (recv(selFd, drain, sizeof(drain), 0) > 0) {}
        }
    }

    int batchFd = -1;
    const bool hasOtherServers = (scanN > (selFd >= 0 ? 1u : 0u));
    if (hasOtherServers) {
        if (g_scanUdpFd < 0) {
            g_scanUdpFd = socket(AF_INET, SOCK_DGRAM, 0);
            if (g_scanUdpFd >= 0)
                HttpSetNonBlock(g_scanUdpFd, true);
        }
        batchFd = g_scanUdpFd;
        if (batchFd >= 0) {
            u8 drain[1024];
            while (recvfrom(batchFd, drain, sizeof(drain), 0, nullptr, nullptr) > 0) {}
        }
    }
    if (selFd < 0 && batchFd < 0)
        return;

    static char s_seen[kStatMaxServers][kMaxScanRooms][36];
    u32 seenN[kStatMaxServers] = {};
    s32 udpOnline[kStatMaxServers] = {};

    memset(g_frags, 0, sizeof(g_frags));
    Deadline start = std::chrono::steady_clock::now();
    Deadline deadline = start + std::chrono::milliseconds(kBatchScanMs);
    Deadline nextSend = start;
    u8 frame[2048];

    auto processRoomFrame = [&](u32 matchS, ssize_t n) {
        u32 idx = scanIdxs[matchS];
        if (items[idx].rooms < 0)
            items[idx].rooms = 0;

        const u8 *pkt = nullptr;
        size_t pktLen = 0;
        if (frame[0] == 1) {
            pkt = frame + 1;
            pktLen = (size_t)n - 1;
        } else if (frame[0] == 3) {
            if (n >= 5 && (s32)idx != selIdx) {
                u32 origIp = 0;
                memcpy(&origIp, frame + 1, 4);
                u32 tagIp = origIp ^ ((idx + 1u) << 24);
                memcpy(frame + 1, &tagIp, 4);
            }
            if (!FragAdd(frame + 1, (size_t)n - 1, &pkt, &pktLen))
                return;
        } else {
            return;
        }

        MonitorRoom room;
        memset(&room, 0, sizeof(room));
        char tag[36] = {};
        if (!ParseLdnResponse(pkt, pktLen, &room, tag, sizeof(tag)))
            return;

        for (u32 k = 0; k < seenN[matchS]; k++) {
            if (strcmp(s_seen[matchS][k], tag) == 0)
                return;
        }
        if (seenN[matchS] < kMaxScanRooms)
            snprintf(s_seen[matchS][seenN[matchS]++], sizeof(s_seen[matchS][0]), "%s", tag);

        items[idx].rooms++;
        udpOnline[matchS] += (room.players > 0) ? (s32)room.players : 1;
        if ((s32)idx == selIdx && selQr && selQr->roomN < MONITOR_MAX_ROOMS)
            selQr->rooms[selQr->roomN++] = room;
    };

    while (std::chrono::steady_clock::now() < deadline && !IoAbort()) {
        Deadline now = std::chrono::steady_clock::now();
        if (now >= nextSend) {
            for (u32 s = 0; s < scanN; s++) {
                u32 idx = scanIdxs[s];
                if ((s32)s == selScanSlot && selFd >= 0) {
                    if (send(selFd, kScanFrame, sizeof(kScanFrame), 0) >= 0)
                        items[idx].didScan = true;
                } else if (batchFd >= 0) {
                    if (sendto(batchFd, kScanFrame, sizeof(kScanFrame), 0,
                               (struct sockaddr *)&items[idx].sa, sizeof(items[idx].sa)) >= 0) {
                        items[idx].didScan = true;
                    }
                }
            }
            nextSend = now + std::chrono::milliseconds(280);
        }
        fd_set rset;
        FD_ZERO(&rset);
        int maxFd = -1;
        if (selFd >= 0) {
            FD_SET(selFd, &rset);
            if (selFd > maxFd) maxFd = selFd;
        }
        if (batchFd >= 0) {
            FD_SET(batchFd, &rset);
            if (batchFd > maxFd) maxFd = batchFd;
        }
        struct timeval tv = { 0, 10 * 1000 };
        int sel = select(maxFd + 1, &rset, nullptr, nullptr, &tv);
        if (sel <= 0)
            continue;

        if (selFd >= 0 && selScanSlot >= 0 && FD_ISSET(selFd, &rset)) {
            for (;;) {
                ssize_t n = recv(selFd, frame, sizeof(frame), 0);
                if (n <= 0)
                    break;
                processRoomFrame((u32)selScanSlot, n);
            }
        }
        if (batchFd >= 0 && FD_ISSET(batchFd, &rset)) {
            for (;;) {
                struct sockaddr_in fromSa;
                socklen_t fromLen = sizeof(fromSa);
                memset(&fromSa, 0, sizeof(fromSa));
                ssize_t n = recvfrom(batchFd, frame, sizeof(frame), 0,
                                     (struct sockaddr *)&fromSa, &fromLen);
                if (n <= 0)
                    break;

                s32 matchS = -1;
                for (u32 s = 0; s < scanN; s++) {
                    if ((s32)s == selScanSlot && selFd >= 0)
                        continue;
                    u32 idx = scanIdxs[s];
                    if (items[idx].sa.sin_addr.s_addr == fromSa.sin_addr.s_addr &&
                        items[idx].sa.sin_port == fromSa.sin_port) {
                        matchS = (s32)s;
                        break;
                    }
                }
                if (matchS >= 0)
                    processRoomFrame((u32)matchS, n);
            }
        }
    }

    for (u32 s = 0; s < scanN; s++) {
        u32 idx = scanIdxs[s];
        if (udpOnline[s] > items[idx].online)
            items[idx].online = udpOnline[s];
        if ((s32)idx == selIdx && selQr) {
            if (items[idx].online > selQr->online)
                selQr->online = items[idx].online;
            if (selQr->roomN > 0)
                items[idx].httpOk = true;
        }
    }
}

struct BatchHttpSlot {
    int  srvIdx = -1;
    int  fd = -1;
    int  state = 0;          /* 0=空闲, 1=连接中, 2=发送中, 3=接收中 */
    bool restMode = false;
    bool triedGql = false;
    bool triedRest = false;
    u8   gqlVariant = 0;
    std::string req;
    size_t sent = 0;
    std::string raw;
    bool gotFirstByte = false;
    Deadline start{};
    Deadline deadline{};
};

/* 同步批量探测所有服务器(选中服 + 全部其它服):
 *   1. BatchResolveAll 一次性解析全部域名;
 *   2. 1 个共享 UDP 套接字并发向全部服务器发送 5 字节中继 PING ({0x02,'l','d',tag,'p'}),
 *      其中 tag = (attempt<<6)|idx,1.0 与 2.0/3.0 服务器均原样回显前 4 字节;
 *   3. 4 个非阻塞 TCP 套接字滑动窗口并发查询全部服务器的 GraphQL / REST /info
 *      (选中服务器排在第 0 号槽位最先启动);
 *   4. 对所有 online > 0 且 rooms == 0 的服务器并发执行 BatchUdpRoomScan。 */
static void RefreshAllServersBatch(const char *selHost, u16 selPort,
                                   QueryResult *selQr, bool *selOkOut,
                                   s32 *selLatOut, int *selHttpErrOut) {
    *selQr = QueryResult{};
    if (selOkOut) *selOkOut = false;
    if (selLatOut) *selLatOut = 0;
    if (selHttpErrOut) *selHttpErrOut = 0;
    if (!g_sockInited) {
        if (selHttpErrOut) *selHttpErrOut = 1;
        return;
    }

    char selAddr[64];
    snprintf(selAddr, sizeof(selAddr), "%.55s:%u", selHost, (unsigned)selPort);

    u32 count = 0;
    s32 selIdx = -1;
    s32 selCachedRooms = 0;
    const u64 nowMs = MonNowMs();
    {
        std::scoped_lock lk(g_mutex);
        for (u32 i = 0; i < MONITOR_MAX_ROOMS; i++) {
            if (g_roomCache[i].used)
                selCachedRooms++;
        }
        count = g_statCount;
        if (count > kStatMaxServers)
            count = kStatMaxServers;
        for (u32 i = 0; i < count; i++) {
            memset(&g_batch[i], 0, sizeof(g_batch[i]));
            snprintf(g_batch[i].addr, sizeof(g_batch[i].addr), "%s", g_stats[i].addr);
            SplitAddrHostPort(g_stats[i].addr, g_batch[i].host, sizeof(g_batch[i].host), &g_batch[i].port);
            g_batch[i].proto = g_stats[i].proto;
            if (g_batch[i].proto == ProtoUnknown)
                g_batch[i].proto = DefaultProtoForHostPort(g_batch[i].host, g_batch[i].port);
            g_batch[i].hadRecentScan = (g_stats[i].lastScanMs != 0 &&
                                        nowMs >= g_stats[i].lastScanMs &&
                                        (nowMs - g_stats[i].lastScanMs) < 30000);
            g_batch[i].prevRooms = g_stats[i].rooms > 0 ? g_stats[i].rooms : 0;
            g_batch[i].rawOnline = -1;
            g_batch[i].online = -1;
            g_batch[i].rooms = -1;
            if (strcmp(g_batch[i].addr, selAddr) == 0)
                selIdx = (s32)i;
        }
    }
    if (selIdx < 0 && count < kStatMaxServers) {
        selIdx = (s32)count++;
        memset(&g_batch[selIdx], 0, sizeof(g_batch[selIdx]));
        snprintf(g_batch[selIdx].addr, sizeof(g_batch[selIdx].addr), "%s", selAddr);
        snprintf(g_batch[selIdx].host, sizeof(g_batch[selIdx].host), "%s", selHost);
        g_batch[selIdx].port = selPort;
        g_batch[selIdx].proto = DefaultProtoForHostPort(selHost, selPort);
        g_batch[selIdx].rawOnline = -1;
        g_batch[selIdx].online = -1;
        g_batch[selIdx].rooms = -1;
    }
    if (selIdx >= 0 && selCachedRooms > g_batch[selIdx].prevRooms)
        g_batch[selIdx].prevRooms = selCachedRooms;
    g_batchCount = count;
    if (count == 0 || IoAbort())
        return;

    BatchResolveAll(g_batch, count);
    if (IoAbort())
        return;

    /* 队列顺序:选中服务器排第 0 位优先跑,其余服务器紧随其后 */
    u32 order[kStatMaxServers];
    u32 orderN = 0;
    if (selIdx >= 0 && g_batch[selIdx].resolved)
        order[orderN++] = (u32)selIdx;
    for (u32 i = 0; i < count; i++) {
        if ((s32)i != selIdx && g_batch[i].resolved)
            order[orderN++] = i;
    }
    if (selIdx >= 0 && !g_batch[selIdx].resolved && selHttpErrOut)
        *selHttpErrOut = 2;

    int pingFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (pingFd >= 0)
        HttpSetNonBlock(pingFd, true);
    Deadline pingSend[2][kStatMaxServers] = {};
    Deadline loopStart = std::chrono::steady_clock::now();
    if (pingFd >= 0) {
        for (u32 i = 0; i < count; i++) {
            if (!g_batch[i].resolved)
                continue;
            pingSend[0][i] = std::chrono::steady_clock::now();
            u8 pkt[5] = { 0x02, 'l', 'd', (u8)(i & 0x3F), 'p' };
            sendto(pingFd, pkt, sizeof(pkt), 0,
                   (struct sockaddr *)&g_batch[i].sa, sizeof(g_batch[i].sa));
        }
    }
    bool pingResent = false;

    static const char *const kGqlVariants[4] = {
        kGraphqlQuery,
        kGraphqlQueryNoAdvert,
        kGraphqlQueryNoConnection,
        kGraphqlQueryOldest,
    };
    static BatchHttpSlot slots[kBatchHttpSlots];
    for (int s = 0; s < kBatchHttpSlots; s++)
        slots[s] = BatchHttpSlot{};

    auto launchSlot = [&](BatchHttpSlot &sl, int idx, bool restMode, u8 gqlVar) {
        sl.srvIdx = idx;
        sl.restMode = restMode;
        sl.gqlVariant = gqlVar;
        if (restMode)
            sl.triedRest = true;
        else
            sl.triedGql = true;
        sl.sent = 0;
        sl.raw.clear();
        sl.gotFirstByte = false;
        sl.start = std::chrono::steady_clock::now();
        sl.deadline = sl.start + std::chrono::milliseconds(kBatchHttpMs);

        sl.fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sl.fd < 0) {
            sl.state = 0;
            g_batch[idx].httpErr = 3;
            return false;
        }
        HttpSetNonBlock(sl.fd, true);

        if (restMode) {
            char hdr[320];
            snprintf(hdr, sizeof(hdr),
                     "GET /info HTTP/1.1\r\n"
                     "Host: %s:%u\r\n"
                     "User-Agent: ldn_mitm/1.0\r\n"
                     "Accept: */*\r\n"
                     "Connection: close\r\n\r\n",
                     g_batch[idx].host, (unsigned)g_batch[idx].port);
            sl.req = hdr;
        } else {
            const char *qstr = (idx == selIdx) ? kGqlVariants[gqlVar < 4 ? gqlVar : 3]
                                               : kGraphqlQueryOldest;
            std::string body = "{\"query\":\"";
            body += qstr;
            body += "\"}";
            char hdr[384];
            snprintf(hdr, sizeof(hdr),
                     "POST / HTTP/1.1\r\n"
                     "Host: %s:%u\r\n"
                     "User-Agent: ldn_mitm/1.0\r\n"
                     "Accept: */*\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n\r\n",
                     g_batch[idx].host, (unsigned)g_batch[idx].port, body.size());
            sl.req = hdr;
            sl.req += body;
        }

        int rc = connect(sl.fd, (struct sockaddr *)&g_batch[idx].sa, sizeof(g_batch[idx].sa));
        if (rc == 0) {
            sl.state = 2;
            return true;
        }
        if (errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EAGAIN) {
            sl.state = 1;
            return true;
        }
        close(sl.fd);
        sl.fd = -1;
        sl.state = 0;
        g_batch[idx].httpErr = 4;
        return false;
    };

    u32 nextOrder = 0;
    auto assignNextServer = [&](BatchHttpSlot &sl) {
        while (nextOrder < orderN) {
            int idx = (int)order[nextOrder++];
            sl = BatchHttpSlot{};
            bool startRest = (g_batch[idx].proto == ProtoRest);
            if (launchSlot(sl, idx, startRest, 0))
                return;
            if (!startRest && launchSlot(sl, idx, true, 0))
                return;
        }
    };

    for (int s = 0; s < kBatchHttpSlots && nextOrder < orderN; s++)
        assignNextServer(slots[s]);

    static QueryResult s_auxQr;
    auto completeSlot = [&](BatchHttpSlot &sl, bool hasResponse, int transportErr) {
        int idx = sl.srvIdx;
        if (sl.fd >= 0) {
            close(sl.fd);
            sl.fd = -1;
        }
        sl.state = 0;

        bool retrySchema = false;
        int parseErr = transportErr;
        QueryResult *targetQr = (idx == selIdx) ? selQr : &s_auxQr;
        bool ok = false;
        if (hasResponse)
            ok = ParseBatchHttpResponse(sl.raw, sl.restMode, targetQr, &retrySchema, &parseErr);

        if (ok) {
            g_batch[idx].rawOnline = targetQr->online;
            if (g_batch[idx].hadRecentScan && targetQr->online > 0 &&
                (targetQr->online >= 2 || (targetQr->roomN == 0 && g_batch[idx].prevRooms == 0))) {
                targetQr->online--;
            }
            g_batch[idx].httpOk = true;
            g_batch[idx].httpErr = 0;
            g_batch[idx].online = targetQr->online;
            g_batch[idx].rooms = (s32)targetQr->roomN;
            g_batch[idx].proto = sl.restMode ? ProtoRest : ProtoGraphql;
        } else {
            g_batch[idx].httpErr = parseErr;
            if (hasResponse) {
                if (!sl.restMode && retrySchema && idx == selIdx && sl.gqlVariant + 1 < 4) {
                    if (launchSlot(sl, idx, false, (u8)(sl.gqlVariant + 1)))
                        return;
                }
                if (!sl.triedRest) {
                    if (launchSlot(sl, idx, true, 0))
                        return;
                } else if (!sl.triedGql) {
                    if (launchSlot(sl, idx, false, 0))
                        return;
                }
            }
        }
        assignNextServer(sl);
    };

    while (!IoAbort()) {
        Deadline now = std::chrono::steady_clock::now();
        long elapsedMs = (long)std::chrono::duration_cast<std::chrono::milliseconds>(now - loopStart).count();
        if (pingFd >= 0 && !pingResent && elapsedMs >= 320) {
            pingResent = true;
            for (u32 i = 0; i < count; i++) {
                if (g_batch[i].resolved && g_batch[i].latMs == 0) {
                    pingSend[1][i] = std::chrono::steady_clock::now();
                    u8 pkt[5] = { 0x02, 'l', 'd', (u8)(0x40 | (i & 0x3F)), 'p' };
                    sendto(pingFd, pkt, sizeof(pkt), 0,
                           (struct sockaddr *)&g_batch[i].sa, sizeof(g_batch[i].sa));
                }
            }
        }

        fd_set rset, wset;
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        int maxFd = -1;
        if (pingFd >= 0) {
            FD_SET(pingFd, &rset);
            maxFd = pingFd;
        }

        bool anyHttpActive = false;
        for (int s = 0; s < kBatchHttpSlots; s++) {
            BatchHttpSlot &sl = slots[s];
            if (sl.state == 0)
                continue;
            if (now >= sl.deadline) {
                completeSlot(sl, !sl.raw.empty(), 6);
                if (sl.state == 0)
                    continue;
            }
            anyHttpActive = true;
            if (sl.fd > maxFd)
                maxFd = sl.fd;
            if (sl.state == 1 || sl.state == 2)
                FD_SET(sl.fd, &wset);
            else if (sl.state == 3)
                FD_SET(sl.fd, &rset);
        }

        bool allPingsDone = true;
        for (u32 i = 0; i < count; i++) {
            if (g_batch[i].resolved && g_batch[i].latMs == 0) {
                allPingsDone = false;
                break;
            }
        }
        if (!anyHttpActive && (pingFd < 0 || allPingsDone || elapsedMs >= 600))
            break;
        if (maxFd < 0)
            break;

        struct timeval tv = { 0, 10 * 1000 };
        int sel = select(maxFd + 1, &rset, &wset, nullptr, &tv);
        if (sel <= 0)
            continue;
        now = std::chrono::steady_clock::now();

        if (pingFd >= 0 && FD_ISSET(pingFd, &rset)) {
            u8 reply[32];
            for (;;) {
                ssize_t n = recv(pingFd, reply, sizeof(reply), 0);
                if (n < 4)
                    break;
                if (reply[0] == 0x02 && reply[1] == 'l' && reply[2] == 'd') {
                    u32 att = (reply[3] >> 6) & 1u;
                    u32 idx = reply[3] & 0x3Fu;
                    if (idx < count && g_batch[idx].latMs == 0 &&
                        pingSend[att][idx].time_since_epoch().count() != 0) {
                        s32 ms = (s32)std::chrono::duration_cast<std::chrono::milliseconds>(
                            now - pingSend[att][idx]).count();
                        g_batch[idx].latMs = ms > 0 ? ms : 1;
                    }
                }
            }
        }

        for (int s = 0; s < kBatchHttpSlots; s++) {
            BatchHttpSlot &sl = slots[s];
            if (sl.state == 0 || sl.fd < 0)
                continue;
            if (sl.state == 1 && FD_ISSET(sl.fd, &wset)) {
                int soErr = 0;
                socklen_t slen = sizeof(soErr);
                if (getsockopt(sl.fd, SOL_SOCKET, SO_ERROR, &soErr, &slen) != 0 || soErr != 0) {
                    completeSlot(sl, false, 4);
                    continue;
                }
                sl.state = 2;
            }
            if (sl.state == 2 && sl.fd >= 0 && FD_ISSET(sl.fd, &wset)) {
                ssize_t n = send(sl.fd, sl.req.data() + sl.sent, sl.req.size() - sl.sent, 0);
                if (n < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        completeSlot(sl, false, 5);
                } else if (n == 0) {
                    completeSlot(sl, false, 5);
                } else {
                    sl.sent += (size_t)n;
                    if (sl.sent >= sl.req.size())
                        sl.state = 3;
                }
            }
            if (sl.state == 3 && sl.fd >= 0 && FD_ISSET(sl.fd, &rset)) {
                char buf[2048];
                ssize_t n = recv(sl.fd, buf, sizeof(buf), 0);
                if (n < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        completeSlot(sl, !sl.raw.empty(), 6);
                } else if (n == 0) {
                    completeSlot(sl, !sl.raw.empty(), 7);
                } else {
                    if (!sl.gotFirstByte) {
                        sl.gotFirstByte = true;
                        s32 rtt = (s32)std::chrono::duration_cast<std::chrono::milliseconds>(
                            now - sl.start).count() / 2;
                        g_batch[sl.srvIdx].httpRttMs = rtt > 0 ? rtt : 1;
                    }
                    sl.raw.append(buf, (size_t)n);
                    if (sl.raw.size() >= kMaxHttpBody) {
                        completeSlot(sl, true, 0);
                        continue;
                    }
                    size_t hdrEnd = sl.raw.find("\r\n\r\n");
                    if (hdrEnd != std::string::npos) {
                        long contentLen = -1;
                        for (size_t p = 0; p < hdrEnd; ) {
                            size_t e = sl.raw.find("\r\n", p);
                            if (e == std::string::npos || e > hdrEnd)
                                break;
                            if (e - p >= 15 &&
                                strncasecmp(sl.raw.c_str() + p, "Content-Length:", 15) == 0) {
                                contentLen = atol(sl.raw.c_str() + p + 15);
                                break;
                            }
                            p = e + 2;
                        }
                        if (contentLen >= 0 &&
                            sl.raw.size() >= hdrEnd + 4 + (size_t)contentLen) {
                            completeSlot(sl, true, 0);
                        }
                    }
                }
            }
        }
    }

    if (pingFd >= 0)
        close(pingFd);
    for (int s = 0; s < kBatchHttpSlots; s++) {
        if (slots[s].fd >= 0) {
            close(slots[s].fd);
            slots[s].fd = -1;
        }
        slots[s].state = 0;
    }
    if (IoAbort())
        return;

    /* 收集需要 UDP 房间扫描的服务器:
     *   - 选中服务器:只要 HTTP 未给出房间且(rawOnline > 0 或已有缓存房间或 HTTP 偶发失败),一律做 UDP 扫描;
     *   - 其余服务器:HTTP 成功且未返回房间,同时(online > 0 或上一轮存在房间 prevRooms > 0)时做 UDP 扫描。 */
    u32 scanIdxs[kStatMaxServers];
    u32 scanN = 0;
    if (selIdx >= 0 && g_batch[selIdx].resolved && g_batch[selIdx].rooms <= 0 &&
        (!g_batch[selIdx].httpOk || g_batch[selIdx].rawOnline > 0 ||
         g_batch[selIdx].online > 0 || g_batch[selIdx].prevRooms > 0)) {
        scanIdxs[scanN++] = (u32)selIdx;
    }
    for (u32 i = 0; i < count; i++) {
        if ((s32)i != selIdx && g_batch[i].httpOk && g_batch[i].rooms == 0 &&
            (g_batch[i].online > 0 || g_batch[i].prevRooms > 0)) {
            scanIdxs[scanN++] = i;
        }
    }
    if (scanN > 0 && !IoAbort())
        BatchUdpRoomScan(g_batch, scanIdxs, scanN, selIdx, selQr);
    if (IoAbort())
        return;

    for (u32 i = 0; i < count; i++) {
        if (g_batch[i].latMs <= 0 && g_batch[i].httpRttMs > 0)
            g_batch[i].latMs = g_batch[i].httpRttMs;
    }

    if (selIdx >= 0) {
        if (selOkOut) *selOkOut = g_batch[selIdx].httpOk;
        if (selLatOut) *selLatOut = g_batch[selIdx].latMs;
        if (selHttpErrOut) *selHttpErrOut = g_batch[selIdx].httpErr;
    }
}

/* 在持有 g_mutex 的情况下将本轮批量探测结果一次性写入 g_stats[]。 */
static void StatsCommitBatchLocked(const char *selHost, u16 selPort,
                                   s32 selOnline, s32 selRooms, s32 selLat) {
    const u64 nowMs = MonNowMs();
    char selAddr[64];
    snprintf(selAddr, sizeof(selAddr), "%.55s:%u", selHost, (unsigned)selPort);

    for (u32 i = 0; i < g_batchCount; i++) {
        const BatchServerItem &b = g_batch[i];
        for (u32 k = 0; k < g_statCount; k++) {
            if (strcmp(g_stats[k].addr, b.addr) != 0)
                continue;
            ServerStat &st = g_stats[k];
            if (b.proto != ProtoUnknown)
                st.proto = b.proto;
            if (b.didScan)
                st.lastScanMs = nowMs;
            if (strcmp(st.addr, selAddr) == 0) {
                st.failCount = 0;
                st.online = selOnline;
                st.rooms = selRooms;
                st.roomMissingSinceMs = 0;
                if (selLat > 0)
                    st.latencyMs = selLat;
                st.stampMs = nowMs;
            } else if (b.httpOk) {
                st.failCount = 0;
                if (b.rooms > 0) {
                    st.rooms = b.rooms;
                    st.roomMissingSinceMs = 0;
                    st.online = b.online >= b.rooms ? b.online : b.rooms;
                } else if (st.rooms > 0 && b.rawOnline > 0) {
                    /* 其它服务器房间同样享受 3 秒过期缓存,避免偶发 UDP 丢包让房间数闪烁 */
                    if (st.roomMissingSinceMs == 0) {
                        st.roomMissingSinceMs = nowMs;
                    } else if (nowMs >= st.roomMissingSinceMs &&
                               (nowMs - st.roomMissingSinceMs) >= kRoomExpireGraceMs) {
                        st.rooms = 0;
                        st.roomMissingSinceMs = 0;
                    }
                    if (st.rooms > 0)
                        st.online = b.online >= st.rooms ? b.online : st.rooms;
                    else
                        st.online = b.online;
                } else {
                    st.rooms = b.rooms;
                    st.roomMissingSinceMs = 0;
                    st.online = b.online;
                }
                if (b.latMs > 0)
                    st.latencyMs = b.latMs;
                st.stampMs = nowMs;
            } else {
                if (b.latMs > 0)
                    st.latencyMs = b.latMs;
                st.failCount++;
                const bool keepRecent = (st.stampMs != 0 && nowMs >= st.stampMs &&
                                         (nowMs - st.stampMs) <= kStatKeepOnFailMs &&
                                         st.failCount < 2);
                if (!keepRecent) {
                    st.online = -1;
                    st.rooms = -1;
                    if (b.latMs <= 0)
                        st.latencyMs = 0;
                    st.stampMs = nowMs;
                }
            }
            break;
        }
    }
}

/* 兼容单台 UDP PING 测量(供单点回退使用) */
static s32 ProbeLatencyMs(const char *host, u16 port) {
    struct sockaddr_in sa;
    if (!HttpResolve(host, &sa))
        return 0;
    sa.sin_port = htons(port);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return 0;
    }
    HttpSetNonBlock(fd, true);
    u8 drain[64];
    while (recv(fd, drain, sizeof(drain), 0) > 0) {}

    static const u8 kPing[5] = { 0x02, 'l', 'd', 'n', 'p' };
    s32 ms = 0;
    for (int attempt = 0; attempt < 2 && ms == 0 && !IoAbort(); attempt++) {
        Deadline start = std::chrono::steady_clock::now();
        if (send(fd, kPing, sizeof(kPing), 0) != (ssize_t)sizeof(kPing))
            break;
        Deadline deadline = start + std::chrono::milliseconds(450);
        while (std::chrono::steady_clock::now() < deadline) {
            if (IoAbort()) {
                close(fd);
                return 0;
            }
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(fd, &rset);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 10 * 1000;
            int sel = select(fd + 1, &rset, nullptr, nullptr, &tv);
            if (sel < 0)
                break;
            if (sel == 0)
                continue;
            u8 reply[16];
            ssize_t n = recv(fd, reply, sizeof(reply), 0);
            if (n >= 4 && reply[0] == 0x02) {
                s32 elapsed = (s32)std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                ms = elapsed > 0 ? elapsed : 1;
                break;
            }
        }
    }
    close(fd);
    return ms;
}

u32 MonitorListServerStats(MonitorServerStat *out, u32 max) {
    if (!out || max == 0)
        return 0;
    const u64 now = MonNowMs();
    u32 n = 0;
    std::scoped_lock lk(g_mutex);
    for (u32 k = 0; k < g_statCount && n < max; k++) {
        snprintf(out[n].name, sizeof(out[n].name), "%.31s", g_stats[k].name);
        snprintf(out[n].addr, sizeof(out[n].addr), "%.63s", g_stats[k].addr);
        out[n].online = g_stats[k].online;
        out[n].rooms = g_stats[k].rooms;
        out[n].latencyMs = g_stats[k].latencyMs;
        out[n].ageMs = g_stats[k].stampMs ? (now - g_stats[k].stampMs) : 0;
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* 后台线程(libnx 线程,风格同 libtesla)                               */
/* ------------------------------------------------------------------ */


static void MonitorWorker(void *) {
    /* 线程一起来就把启动阶段欠下的重活做掉:挂载 SD/建目录/补写日志、
     * 堆余量探针、socket 探针。此时 UI 已经在画了,不再阻塞首帧。 */
    if (!g_exit.load()) {
        MonitorOpenLog();
        ProbeHeap();
        if (g_sockInited) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            char m[24];
            snprintf(m, sizeof(m), "soc-probe fd=%d", fd);
            MonLog(m);
            if (fd >= 0)
                close(fd);
        }
        MonLog("worker-ready");
    }

    while (!g_exit.load()) {
        u32 want = g_reqGen.load();
        if (want != g_doneGen.load()) {
            g_doneGen.store(want);
            char name[48];
            bool subs;
            MonitorTargetGeneration::Value targetGen;
            {
                std::scoped_lock lk(g_mutex);
                memcpy(name, g_pendingName, sizeof(name));
                subs = g_pendingSubs;
                g_pendingSubs = false;
                targetGen = g_targetGen.Capture();
                g_auxTargetGen.store(targetGen);
            }
            DoRefresh(name[0] ? name : nullptr, subs, targetGen);
            MonLog("refresh-done");
        } else {
            svcSleepThread(10'000'000);      /* 10ms:按返回退出时无需等 50ms */
        }
    }
}

void MonitorSetTraditional(bool traditional) {
    g_traditional.store(traditional);
}

void MonitorSetPaused(bool paused) {
    g_paused.store(paused);
}

/* 标题表延迟到首次解析时才分配(约 0.5MB),避免在 overlay 刚打开、
 * 渲染器 frameBuffer(约 1.3MB)分配之前就把 ovlloader 仅几 MB 的堆挤爆。 */
static void EnsureTitleTables() {
    if (g_titleKey)
        return;
    g_titleKey   = (u64 *)calloc(kTitleHashSize, sizeof(u64));
    g_titleOff   = (u32 *)calloc(kTitleHashSize, sizeof(u32));
    g_titleLen   = (u16 *)calloc(kTitleHashSize, sizeof(u16));
    g_titleArena = (char *)calloc(kTitleArena, 1);
    if (!g_titleKey || !g_titleOff || !g_titleLen || !g_titleArena) {
        free(g_titleKey); free(g_titleOff); free(g_titleLen); free(g_titleArena);
        g_titleKey = nullptr; g_titleOff = nullptr;
        g_titleLen = nullptr; g_titleArena = nullptr;
    }
}

/* 工作线程优先级:0x3B 比 UI 线程(libtesla 用 0x2C)低,订阅下载/查询
 * 再重也抢不过界面。之前用 0x2C 时,3MB 的订阅下载会把默认线程挤到后面,
 * 表现就是「插件里按返回,特斯拉菜单要等一会儿才出来」。 */
static constexpr int kWorkerPriority = 0x3B;

void MonitorInit() {
    if (g_inited)
        return;
    g_inited = true;
    g_exit.store(false);
    g_paused.store(false);
    g_pendingName[0] = 0;
    MonLog("worker-init");        /* 只进内存缓冲,不碰 SD */

    Result rc = threadCreate(&g_thread, MonitorWorker, nullptr, g_workerStack,
                             sizeof(g_workerStack), kWorkerPriority, -2);
    if (R_SUCCEEDED(rc))
        threadStart(&g_thread);
}

void MonitorExit() {
    if (!g_inited)
        return;
    g_paused.store(true);
    g_exit.store(true);
    threadWaitForExit(&g_thread);
    threadClose(&g_thread);
    if (g_scanUdpFd >= 0) {
        close(g_scanUdpFd);
        g_scanUdpFd = -1;
    }
    if (g_selScanUdpFd >= 0) {
        close(g_selScanUdpFd);
        g_selScanUdpFd = -1;
    }
    if (g_sockInited) {
        socketExit();
        g_sockInited = false;
    }
    g_inited = false;
}

/* Must be called with g_mutex held. Detach the published room list from the
 * previous target immediately, before the blocking worker starts its query. */
static void ResetSnapshotForRequestLocked(const char *serverName,
                                          const char *status) {
    snprintf(g_snap.server, sizeof(g_snap.server), "%.47s",
             serverName ? serverName : "");
    g_snap.online = -1;
    g_snap.roomCount = -1;
    g_snap.roomN = 0;
    memset(g_snap.rooms, 0, sizeof(g_snap.rooms));
    snprintf(g_snap.status, sizeof(g_snap.status), "%s", status);
    g_snap.busy = true;
    g_snap.version++;
}

void MonitorRequestRefresh(const char *serverName) {
    std::scoped_lock lk(g_mutex);
    snprintf(g_pendingName, sizeof(g_pendingName), "%s", serverName ? serverName : "");
    g_pendingSubs = true;      /* 开盖/手动刷新:同时重新拉订阅缓存 */
    g_targetGen.Advance();
    ResetSnapshotForRequestLocked(
        serverName, T_STR("正在刷新服务器…", "正在刷新伺服器…"));
    g_reqGen.fetch_add(1);
}

void MonitorRequestSwitch(const char *serverName) {
    std::scoped_lock lk(g_mutex);
    snprintf(g_pendingName, sizeof(g_pendingName), "%s", serverName ? serverName : "");
    g_targetGen.Advance();
    ResetSnapshotForRequestLocked(
        serverName, T_STR("正在切换服务器…", "正在切換伺服器…"));
    g_reqGen.fetch_add(1);
}

void MonitorRequestPoll() {
    /* 周期刷新(与延迟 ping 同节奏):不动目标、不拉订阅 */
    g_reqGen.fetch_add(1);
}

void MonitorCopySnapshot(MonitorSnapshot *out) {
    std::scoped_lock lk(g_mutex);
    *out = g_snap;
}
