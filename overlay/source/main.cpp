#define TESLA_INIT_IMPL // If you have more than one file using the tesla header, only define this in the main one
#include <tesla.hpp>    // The Tesla Header
#include "ldn.h"
#include <vector>

enum class State {
    Uninit,
    Error,
    Loaded,
};

Service g_ldnSrv;
LdnMitmConfigService g_ldnConfig;
State g_state;
char g_version[32];

/* Brand string shown in the frame header. Must outlive createUI(), because
   OverlayFrame keeps the pointer instead of copying it. */
char g_brand[64] = "阿东版";   // overwritten by detectLanguage() at startup

std::vector<tsl::elm::ListItem*> g_serverItems;

/* Latency value currently painted on the server rows. Lives at file scope
   rather than as a function-local static so createUI() can invalidate it:
   rebuilt rows start with a bare "*", and a stale cache made update() skip
   painting them entirely. */
u32 g_shown_latency = 0xFFFFFFFFu;

/* Traditional / Simplified Chinese switch. The overlay used to hardcode
   Simplified strings, which left Traditional Chinese consoles with the
   wrong glyphs. libtesla already loads both CJK shared fonts, so all we
   need is the console's system language. */
static bool g_isTraditional = false;

#define T(hans, hant) (g_isTraditional ? (hant) : (hans))

class ConfigToggleListItem : public tsl::elm::ToggleListItem {
public:
    ConfigToggleListItem(const char *label,
                         Result (*get)(LdnMitmConfigService *, u32 *),
                         Result (*set)(LdnMitmConfigService *, u32))
        : ToggleListItem(label, false) {
        u32 enabled = 0;
        if (R_FAILED(get(&g_ldnConfig, &enabled))) {
            g_state = State::Error;
        }
        this->setState(enabled);

        this->setStateChangedListener([set](bool enabled) {
            if (R_FAILED(set(&g_ldnConfig, enabled))) {
                g_state = State::Error;
            }
        });
    }
};

static void detectLanguage()
{
    /* setGetSystemLanguage returns the language as an 8-byte ASCII code
       (e.g. "zh-Hans" / "zh-Hant" / "en-US") packed into a u64. */
    u64 langCode = 0;
    if (R_SUCCEEDED(setInitialize())) {
        setGetSystemLanguage(&langCode);
        setExit();
    }
    char code[9] = {};
    memcpy(code, &langCode, 8);
    g_isTraditional = (strncmp(code, "zh-Hant", 7) == 0);

    strcpy(g_brand, g_isTraditional ? "阿東版" : "阿东版");
}

class MainGui : public tsl::Gui {
public:
    MainGui() { }

    virtual tsl::elm::Element* createUI() override {
        // This overlay ships inside a Chinese integration package and the
        // bundled font has CJK glyphs, so the UI is localised in place.
        // The header subtitle carries the release brand; the full version
        // string is repeated in the T("关于", "關於") block at the bottom.
        auto frame = new tsl::elm::OverlayFrame(T("联机插件", "連線插件"), g_brand);

        auto list = new tsl::elm::List();

        if (g_state == State::Error) {
            list->addItem(new tsl::elm::ListItem(T("插件没有加载", "插件沒有載入")));
        } else if (g_state == State::Uninit) {
            list->addItem(new tsl::elm::ListItem(T("错误的状态", "錯誤的狀態")));
        } else {
            list->addItem(new ConfigToggleListItem(T("启用", "啟用"), ldnMitmGetEnabled, ldnMitmSetEnabled));
            list->addItem(new ConfigToggleListItem(T("广播转发", "廣播轉發"), ldnMitmGetBroadcastRelay, ldnMitmSetBroadcastRelay));
            list->addItem(new ConfigToggleListItem(T("日志", "日誌"), ldnMitmGetLogging, ldnMitmSetLogging));

            list->addItem(new tsl::elm::CategoryHeader(T("互联网中继（跨网联机）", "網際網路中繼（跨網連線）")));
            list->addItem(new ConfigToggleListItem(T("互联网中继", "網際網路中繼"), ldnMitmGetInternetRelay, ldnMitmSetInternetRelay));

            g_serverItems.clear();
            u32 count = 0;
            if (R_FAILED(ldnMitmGetRelayServerCount(&g_ldnConfig, &count))) {
                list->addItem(new tsl::elm::ListItem(T("读取服务器列表失败", "讀取伺服器清單失敗")));
            } else if (count == 0) {
                list->addItem(new tsl::elm::ListItem(T("没有服务器，请编辑 relay.cfg", "沒有伺服器，請編輯 relay.cfg")));
            } else {
                u32 selected = 0;
                if (R_FAILED(ldnMitmGetSelectedRelayServer(&g_ldnConfig, &selected))) {
                    selected = count;
                }
                for (u32 i = 0; i < count; i++) {
                    char name[32] = {};
                    ldnMitmGetRelayServerName(&g_ldnConfig, i, name);
                    auto *item = new tsl::elm::ListItem(name);
                    item->setValue(i == selected ? "*" : "");
                    item->setClickListener([i](u64 keys) {
                        if (keys & HidNpadButton_A) {
                            if (R_FAILED(ldnMitmSetSelectedRelayServer(&g_ldnConfig, i))) {
                                g_serverItems[i]->setValue(T("错误", "錯誤"));
                                return true;
                            }
                            for (size_t k = 0; k < g_serverItems.size(); k++) {
                                g_serverItems[k]->setValue(k == i ? "*" : "");
                            }
                            // The loop above just wiped every latency label back
                            // to a bare "*". Invalidate the cache so the next
                            // update() repaints, otherwise the rows would sit
                            // there with only a star until the overlay is
                            // reopened.
                            g_shown_latency = 0xFFFFFFFFu;
                            return true;
                        }
                        return false;
                    });
                    g_serverItems.push_back(item);
                    list->addItem(item);
                }
            }

            // Show this console's relay identity. relay.cfg only stores the
            // low 16 bits (`id=`), and the plugin assigns one on first use if
            // the line is absent, so this is the only place to read it back.
            list->addItem(new tsl::elm::CategoryHeader(T("本机身份", "本機身分")));

            // The relay address is derived from this LAN address, so showing
            // it makes it obvious why the two consoles get different ids.
            // nifm only hands out an address once the LAN session exists, so
            // before the game creates or joins a room there is nothing to
            // read -- that is expected, not a failure.
            u32 local_ip = 0;
            if (R_SUCCEEDED(ldnMitmGetRelayLocalIp(&g_ldnConfig, &local_ip)) && local_ip != 0) {
                char ipbuf[32];
                snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                         (local_ip >> 24) & 0xff, (local_ip >> 16) & 0xff,
                         (local_ip >> 8) & 0xff, local_ip & 0xff);
                list->addItem(new tsl::elm::ListItem(T("本机 IP", "本機 IP"), ipbuf));
            } else {
                list->addItem(new tsl::elm::ListItem(T("本机 IP", "本機 IP"), T("建立房间后显示", "建立房間後顯示")));
            }

            u32 vaddr = 0;
            const bool addr_ok = R_SUCCEEDED(ldnMitmGetRelayVirtualAddress(&g_ldnConfig, &vaddr));
            if (!addr_ok) {
                list->addItem(new tsl::elm::ListItem(T("虚拟地址", "虛擬位址"), T("读取失败", "讀取失敗")));
            } else if (vaddr == 0) {
                list->addItem(new tsl::elm::ListItem(T("虚拟地址", "虛擬位址"), T("建立房间后分配", "建立房間後分配")));
            } else {
                char buf[48];
                snprintf(buf, sizeof(buf), "%u.%u.%u.%u  (id=%u)",
                         (vaddr >> 24) & 0xff, (vaddr >> 16) & 0xff,
                         (vaddr >> 8) & 0xff, vaddr & 0xff, vaddr & 0xffff);
                list->addItem(new tsl::elm::ListItem(T("虚拟地址", "虛擬位址"), buf));
            }

            // Tell the user whether the address is stable. T("硬件派生", "硬體衍生") is
            // derived from this console's LAN address, so it is the same on
            // every boot even when the SD card is write-protected. T("启动随机", "啟動隨機")
            // still gets written to relay.cfg, so check it again after a
            // reboot -- if the number changes, the write is failing.
            if (addr_ok && vaddr != 0) {
                u32 src = 0;
                if (R_FAILED(ldnMitmGetRelayIdSource(&g_ldnConfig, &src))) {
                    src = 0;
                }
                if (src == 1) {
                    list->addItem(new tsl::elm::ListItem(T("地址固定", "位址固定"), T("硬件派生", "硬體衍生")));
                } else if (src == 2) {
                    list->addItem(new tsl::elm::ListItem(T("地址固定", "位址固定"), T("启动随机", "啟動隨機")));
                } else if (src == 3) {
                    list->addItem(new tsl::elm::ListItem(T("地址固定", "位址固定"), T("已自动更换", "已自動更換")));
                } else {
                    // The id either predates hardware derivation or was cached
                    // before this console's LAN address changed.
                    list->addItem(new tsl::elm::ListItem(T("地址固定", "位址固定"), T("未知来源", "未知來源")));
                }
            }
            list->addItem(new tsl::elm::ListItem(T("两台机器的地址必须不同", "兩台機器的位址必須不同")));
            list->addItem(new tsl::elm::ListItem(T("重启后地址不变即正常", "重新啟動後位址不變即正常")));

            // Release signature. Kept at the very bottom so it never gets in
            // the way of the settings, but every user scrolling down sees it.
            list->addItem(new tsl::elm::CategoryHeader(T("关于", "關於")));
            list->addItem(new tsl::elm::ListItem(T("制作", "製作"), T("阿东 & 大肥鱼", "阿東 & 大肥魚")));
            list->addItem(new tsl::elm::ListItem(T("版本", "版本"), g_version));
            list->addItem(new tsl::elm::ListItem(T("声明", "聲明"), T("免费分享 禁止倒卖", "免費分享 禁止轉賣")));
        }

        frame->setContent(list);

        // Every item was just created with a bare "*". Force the first
        // update() to paint the latency text even if the reading has not
        // changed since the last time the overlay was open -- otherwise the
        // cached value made update() return early and the label stayed at
        // just "*" with no "--" and no number.
        g_shown_latency = 0xFFFFFFFFu;

        return frame;
    }

    // Called once every frame to update values
    virtual void update() override {
        // Show the live relay latency next to the selected server.
        // Only the selected server is connected, so it is the only one
        // whose round-trip time we can actually know.
        if (g_state != State::Loaded || g_serverItems.empty()) {
            return;
        }
        u32 ms = 0;
        if (R_FAILED(ldnMitmGetRelayLatency(&g_ldnConfig, &ms))) {
            return;
        }
        // Rebuild the label only when the measurement actually changes.
        if (ms == g_shown_latency) {
            return;
        }
        g_shown_latency = ms;

        // ListItem::setValue(value, faint): faint=false renders in the
        // highlight colour, faint=true in the dim description colour. That
        // gives a green / grey traffic light without a custom element.
        char buf[48];
        bool faint = false;
        if (ms == 0) {
            snprintf(buf, sizeof(buf), T("* 延迟 --", "* 延遲 --"));
            faint = true;
        } else if (ms > 999) {
            snprintf(buf, sizeof(buf), T("* 延迟 >999ms", "* 延遲 >999ms"));
            faint = true;
        } else {
            snprintf(buf, sizeof(buf), T("* 延迟 %ums", "* 延遲 %ums"), ms);
        }
        for (size_t k = 0; k < g_serverItems.size(); k++) {
            if (!g_serverItems[k]->getValue().empty()) {
                g_serverItems[k]->setValue(buf, faint);
            }
        }
    }

    // Called once every frame to handle inputs not handled by other UI elements
    virtual bool handleInput(u64 keysDown, u64 keysHeld, const HidTouchState &touchPos, HidAnalogStickState joyStickPosLeft, HidAnalogStickState joyStickPosRight) {
        return false;
    }
};

class Overlay : public tsl::Overlay {
public:
    virtual void initServices() override {
        g_state = State::Uninit;
        detectLanguage();
        tsl::hlp::doWithSmSession([&] {
            Result rc;

            rc = smGetService(&g_ldnSrv, "ldn:u");
            if (R_FAILED(rc)) {
                g_state = State::Error;
                return;
            }

            rc = ldnMitmGetConfigFromService(&g_ldnSrv, &g_ldnConfig);
            if (R_FAILED(rc)) {
                g_state = State::Error;
                return;
            }

            rc = ldnMitmGetVersion(&g_ldnConfig, g_version);
            if (R_FAILED(rc)) {
                strcpy(g_version, T("错误", "錯誤"));
            }

            g_state = State::Loaded;
        });

    }
    virtual void exitServices() override {
        serviceClose(&g_ldnConfig.s);
        serviceClose(&g_ldnSrv);
    }

    virtual void onShow() override {}    // Called before overlay wants to change from invisible to visible state
    virtual void onHide() override {}    // Called before overlay wants to change from visible to invisible state

    virtual std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<MainGui>();  // Initial Gui to load. It's possible to pass arguments to it's constructor like this
    }
};

int main(int argc, char **argv) {
    return tsl::loop<Overlay>(argc, argv);
}
