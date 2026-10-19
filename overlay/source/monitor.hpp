#pragma once
#include <switch.h>

/* 联机监视器:当前中继服务器的在线人数 / 房间数 / 游戏房间列表。
 *
 * 数据来源:
 *   1. 服务器列表      relay.cfg(与 sysmodule LoadConfig 同解析;servers.json 已移除)
 *   2. 标题映射订阅    chinese_db.json (标题ID -> 中文名)
 *   3. 服务器自身的查询接口(graphql POST / 或 rest GET /info),
 *      rest 服务器接口不给房间时用 UDP 主动扫描补上。
 *
 * chinese_db.json 每次打开 overlay 从远程重新下载(HTTPS 加速镜像
 * https://v6.gh-proxy.org/ 优先),落盘到
 * sdmc:/config/ldn_mitm/ 下供下次离线兜底。
 */

#define MONITOR_MAX_ROOMS  32
#define MONITOR_MAX_SERVERS 32
#define MONITOR_MAX_PLAYERS 8
#define MONITOR_PLAYER_LEN  32

struct MonitorRoom {
    char game[52];      /* 中文游戏名;未映射时是 16 位标题 ID */
    u32  players;       /* 当前人数 */
    u32  playersMax;    /* 人数上限,0 = 未知 */
    u8   playerN;       /* 玩家名有效条数(0 = 服务器未提供名单) */
    char player[MONITOR_MAX_PLAYERS][MONITOR_PLAYER_LEN]; /* 玩家名,房主在 [0] */
    char sessionId[33]; /* 房间标识(sessionId hex;扫描房=标题ID),缓存和去重用 */
};

struct MonitorSnapshot {
    u32 version;        /* 每次查询完成 +1,UI 据此决定是否重建列表 */
    bool busy;          /* 后台正在查询 */
    s32 online;         /* 在线人数,-1 = 未知 */
    s32 roomCount;      /* 房间数量,-1 = 未知 */
    char server[48];    /* 当前选择的服务器名(host:port 兜底) */
    char status[96];    /* 状态文本(错误/提示) */
    u32  roomN;         /* rooms[] 有效条数 */
    MonitorRoom rooms[MONITOR_MAX_ROOMS];
};

void MonitorInit();
void MonitorInitSockets();
void MonitorExit();

/* 简繁文案切换(与 UI 的 T() 同步)。 */
void MonitorSetTraditional(bool traditional);

/* 插件隐藏(onHide)/重新可见(onShow)/按返回退出时置位:隐藏时后台立即放弃
 * 正在进行的下载与查询,别让它们拖住返回特斯拉菜单的那一帧。 */
void MonitorSetPaused(bool paused);

/* 服务器列表:直接读 relay.cfg(第 i 条与 sysmodule 的 g_servers[i] 对应)。
 * addr 形如 "host:port"。 */
struct MonitorServer {
    char name[32];
    char addr[64];
};
u32 MonitorListRelayServers(MonitorServer *out, u32 max);

/* 由 UI 层在构建服务器列表时直接把从 sysmodule 读到的服务器列表同步给监视器,
 * 确保与界面行完全一致且无需在 UI 线程读 SD 卡。 */
void MonitorSetServerList(const MonitorServer *servers, u32 count);

/* 每台服务器自己的在线/房间/延迟(界面所有行都显示,不只是选中行)。
 * 后台线程按轮转顺序逐台探测,所以数值是"最近一次测到的":
 * ageMs = 距上次测量多久(0 = 还没测过)。 */
struct MonitorServerStat {
    char name[32];
    char addr[64];
    s32  online;      /* -1 = 未知 */
    s32  rooms;       /* -1 = 未知 */
    s32  latencyMs;   /* 0 = 未知 */
    u64  ageMs;       /* 距上次测量的毫秒数;0 = 从未测过 */
};

/* 读当前统计表(按 relay.cfg 顺序,与服务器行一一对应)。 */
u32 MonitorListServerStats(MonitorServerStat *out, u32 max);

/* 请求一次后台刷新(每次打开 overlay / 切换服务器时调用)。
 * serverName:选中的服务器名(可空,空则读 relay.cfg 的 selected=)。
 * 非阻塞;完成后 MonitorCopySnapshot 里的 version 会 +1。
 * Refresh = 开盖:改目标 + 重新拉订阅缓存;
 * Switch  = 切换服务器:改目标,不拉订阅;
 * Poll    = 周期刷新(与延迟 ping 同节奏):不动目标、不拉订阅。 */
void MonitorRequestRefresh(const char *serverName);
void MonitorRequestSwitch(const char *serverName);
void MonitorRequestPoll();

/* 取当前快照的副本。 */
void MonitorCopySnapshot(MonitorSnapshot *out);

/* 诊断日志:写 sdmc:/config/ldn_mitm/monitor.log(UI 侧打点用)。 */
void MonitorLog(const char *msg);
