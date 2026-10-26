#define TESLA_INIT_IMPL // If you have more than one file using the tesla header, only define this in the main one
#include <tesla.hpp>    // The Tesla Header
#include "ldn.h"
#include "monitor.hpp"
#include <functional>
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

/* 帧头不再显示「阿东版 · 版本号」副标题(整行区域已移除),版本号仍保留在
   列表底部的「关于」区块里。 */

class ServerRow;
std::vector<ServerRow*> g_serverRows;

/* 在线/房间周期刷新计时(与延迟 ping 的节奏对齐);0 = 尚未起表。 */
static u64 g_lastPollNs = 0;

/* 服务器行三列数值的界面刷新计时(后台探测是另一条线,这里只管取值上屏)。 */
static u64 g_lastStatsNs = 0;

/* 列表重建/切换服务器后:让下一帧立刻重刷三列与延迟。 */
static void invalidateServerStats() {
    g_lastStatsNs = 0;
}

/* overlay 是否可见(onShow/onHide 维护);隐藏时不发周期刷新,不扰网。 */
static bool g_visible = false;

/* Traditional / Simplified Chinese switch. The overlay used to hardcode
   Simplified strings, which left Traditional Chinese consoles with the
   wrong glyphs. libtesla already loads both CJK shared fonts, so all we
   need is the console's system language. */
static bool g_isTraditional = false;

#define T(hans, hant) (g_isTraditional ? (hant) : (hans))

/* The list currently on screen, plus the "restore defaults" row. Both are
   needed after a server is added/removed: libtesla has no per-item refresh,
   so the whole list is rebuilt in place (see rebuildUi()). */
class RebuildList : public tsl::elm::List {
public:
    /* List::clear() resets the scroll position to the top on the frame it
       rebuilds, which made the menu visibly bounce back to the first entry
       before re-focusing the deleted row. Snap straight to the row that is
       about to be focused instead, so the rebuilt list appears in place. */
    void snapToFocus() {
        this->m_offset = this->m_nextOffset;
        this->invalidate();
    }
};

static RebuildList *g_list = nullptr;
static tsl::elm::ListItem *g_restoreItem = nullptr;
static bool g_restoreArmed = false;

/* Rows only enter the List on the next draw, so a rebuilt list cannot take
   focus immediately. update() re-applies this once the target is really in
   the list, which keeps the cursor on the row the user was working on
   instead of snapping back to the first entry. */
static tsl::elm::Element *g_focus_after_rebuild = nullptr;
static int g_focus_retries = 0;

/* Set by the add page. The main list is not the top Gui while that page is
   open, so it rebuilds on the first frame it becomes visible again. */
static bool g_main_list_dirty = false;
static tsl::elm::ListItem *g_addServerItem = nullptr;

static void buildList(tsl::elm::List *list);
static void rebuildUi();

static void focusAfterRebuild(tsl::elm::Element *element) {
    g_focus_after_rebuild = element;
    g_focus_retries = 10;
}


/* ---- 联机监视器(在线/房间/游戏房间)UI 状态 ---- */

/* 当前选中的服务器名,监视器按它查询(切换时立即刷新)。 */
static char g_selectedName[48] = {};

/* 游戏房间区块:标题 + 自绘房间行(持久池,只增不删,焦点安全)。 */
static tsl::elm::CategoryHeader *g_roomHeader = nullptr;
static u32 g_monitorVersion = 0xFFFFFFFFu;   /* 强制首次重建 */
/* 游戏房间标题在列表中的下标;房间行用 addItem 的 index 参数插到它正下方
   (直接 addItem 会被追加到列表末尾,跑到「关于」后面)。 */
static int g_roomHeaderIndex = -1;

class RoomRow;
static std::vector<RoomRow *> g_roomRows;

/* 房间行:与中继服务器列表相同的双排布局(上=游戏标题,下=玩家名),
   始终显示玩家名;固定行高与 ServerRow 一致。 */
static constexpr u16 kMonitorListRowHeight = 70;

class RoomRow : public tsl::elm::Element {
public:
    static constexpr u16 kHeight = kMonitorListRowHeight;
    static constexpr float kTitleFont = 22;
    static constexpr float kPlayerFont = 16;

    RoomRow() { memset(&m_room, 0, sizeof(m_room)); }

    void setRoom(const MonitorRoom &room) {
        m_room = room;
        m_used = true;
        m_hint = false;
        m_measured = false;
    }
    void setHint(const char *text) {
        memset(&m_room, 0, sizeof(m_room));
        snprintf(m_hintText, sizeof(m_hintText), "%s", text);
        m_used = true;
        m_hint = true;
    }
    void clearRow() {
        m_used = false;
        m_hint = false;
    }

    u16 rowHeight() const {
        if (!m_used)
            return 0;
        return m_hint ? 44 : kHeight;
    }

    virtual void layout(u16, u16, u16, u16) override {
        this->setBoundaries(this->getX(), this->getY(), this->getWidth(), rowHeight());
    }

    virtual void draw(tsl::gfx::Renderer *renderer) override {
        using R = tsl::gfx::Renderer;
        if (!m_used)
            return;
        if (m_hint) {
            renderer->drawString(m_hintText, false, this->getX() + 20, this->getY() + 32, 18,
                                 R::a(tsl::style::color::ColorDescription));
            return;
        }

        renderer->drawRect(this->getX(), this->getY(), this->getWidth(), 1,
                           R::a(tsl::style::color::ColorFrame));

        /* 人数(N/M)与上排游戏名同一行、右对齐;名字行不再为它让位,
         * 玩家名单可以用满整行宽度(可以铺到人数下方)。 */
        char val[24];
        if (m_room.playersMax > 0)
            snprintf(val, sizeof(val), "%u/%u", m_room.players, m_room.playersMax);
        else
            snprintf(val, sizeof(val), "%u", m_room.players);
        auto [vw, vh] = renderer->drawString(val, false, 0, 0, 20,
                                             R::a(tsl::style::color::ColorTransparent));
        renderer->drawString(val, false,
                             this->getX() + this->getWidth() - 20 - (s32)vw,
                             this->getY() + 32, 20,
                             R::a(tsl::style::color::ColorHighlight));

        /* 上排只给标题留出人数那一块;下排玩家名用整行宽度。 */
        const s32 titleReserve = 20 + (s32)vw + 12;
        const s32 titleAvail = this->getWidth() - 20 - titleReserve;
        const s32 playerAvail = this->getWidth() - 40;
        const s32 textX = this->getX() + 20;

        /* 上排标题完整显示:宽度不足时整体缩字号,不截标题。 */
        float titleFont = kTitleFont;
        auto [titleW, titleH] = renderer->drawString(m_room.game, false, 0, 0,
                                                      titleFont,
                                                      R::a(tsl::style::color::ColorTransparent));
        if ((s32)titleW > titleAvail && titleW > 0) {
            titleFont *= (float)titleAvail / (float)titleW;
            if (titleFont < 12)
                titleFont = 12;
        }
        renderer->enableScissoring(textX, this->getY() + 6, titleAvail, 30);
        renderer->drawString(m_room.game, false, textX, this->getY() + 32, titleFont,
                             R::a(tsl::style::color::ColorText));
        renderer->disableScissoring();

        /* 下排玩家名:房主高亮,其余名字正常;过长时只在本行窗口内滚动。 */
        const s32 playerY = this->getY() + 58;
        if (m_room.playerN == 0) {
            const char *empty = T("该服务器未提供玩家名单", "該伺服器未提供玩家名單");
            auto [emptyW, emptyH] = renderer->drawString(empty, false, 0, 0,
                                                          kPlayerFont,
                                                          R::a(tsl::style::color::ColorTransparent));
            std::string fit = empty;
            if ((s32)emptyW > playerAvail)
                fit = renderer->limitStringLength(empty, false, kPlayerFont, playerAvail);
            renderer->drawString(fit.c_str(), false, textX, playerY, kPlayerFont,
                                 R::a(tsl::style::color::ColorDescription));
            return;
        }

        if (!m_measured)
            measure(renderer, playerAvail);
        if (m_playerOverflow)
            drawPlayerMarquee(renderer, textX, playerY, playerAvail);
        else
            drawPlayerLine(renderer, textX, playerY, playerAvail);
    }

    virtual tsl::elm::Element *requestFocus(tsl::elm::Element *,
                                            tsl::FocusDirection) override {
        return m_used ? this : nullptr;
    }

    virtual void setFocused(bool state) override {
        m_scrollOff = 0;
        m_scrollCnt = 0;
        tsl::elm::Element::setFocused(state);
    }

private:
    void measure(tsl::gfx::Renderer *renderer, s32 avail) {
        using R = tsl::gfx::Renderer;
        m_measured = true;
        m_hostName = m_room.player[0];
        m_playerSuffix.clear();
        for (u8 i = 1; i < m_room.playerN; i++) {
            m_playerSuffix += " ";
            m_playerSuffix += m_room.player[i];
        }
        m_playerStrip = m_hostName + m_playerSuffix;
        auto [hostW, hostH] = renderer->drawString(m_hostName.c_str(), false, 0, 0,
                                                    kPlayerFont,
                                                    R::a(tsl::style::color::ColorTransparent));
        auto [stripW, stripH] = renderer->drawString(m_playerStrip.c_str(), false, 0, 0,
                                                      kPlayerFont,
                                                      R::a(tsl::style::color::ColorTransparent));
        auto [gapW, gapH] = renderer->drawString("    ", false, 0, 0, kPlayerFont,
                                                 R::a(tsl::style::color::ColorTransparent));
        m_hostWidth = hostW;
        m_stripWidth = stripW;
        m_loopWidth = stripW + gapW;
        m_playerOverflow = (s32)stripW > avail;
        if (m_loopWidth == 0)
            m_loopWidth = 1;
        m_scrollOff %= m_loopWidth;
    }

    void drawPlayerLine(tsl::gfx::Renderer *renderer, s32 x, s32 y, s32 avail) {
        using R = tsl::gfx::Renderer;
        renderer->enableScissoring(x, y - 21, avail, 27);
        renderer->drawString(m_hostName.c_str(), false, x, y, kPlayerFont,
                             R::a(tsl::style::color::ColorHighlight));
        if (!m_playerSuffix.empty())
            renderer->drawString(m_playerSuffix.c_str(), false, x + (s32)m_hostWidth, y,
                                 kPlayerFont, R::a(tsl::style::color::ColorText));
        renderer->disableScissoring();
    }

    void drawPlayerMarquee(tsl::gfx::Renderer *renderer, s32 x, s32 y, s32 avail) {
        using R = tsl::gfx::Renderer;
        if (m_scrollCnt < 90) {
            m_scrollCnt++;
        } else {
            m_scrollCnt = 0;
            m_scrollOff = (m_scrollOff + 1) % m_loopWidth;
        }
        renderer->enableScissoring(x, y - 21, avail, 27);
        for (int copy = 0; copy < 2; copy++) {
            const s32 left = x - (s32)m_scrollOff + copy * (s32)m_loopWidth;
            if (left > x + avail || left + (s32)m_stripWidth < x)
                continue;
            renderer->drawString(m_hostName.c_str(), false, left, y, kPlayerFont,
                                 R::a(tsl::style::color::ColorHighlight));
            if (!m_playerSuffix.empty())
                renderer->drawString(m_playerSuffix.c_str(), false,
                                     left + (s32)m_hostWidth, y, kPlayerFont,
                                     R::a(tsl::style::color::ColorText));
        }
        renderer->disableScissoring();
    }

    MonitorRoom m_room;
    char m_hintText[96] = {};
    bool m_used = false;
    bool m_hint = false;
    bool m_measured = false;
    bool m_playerOverflow = false;
    std::string m_hostName, m_playerSuffix, m_playerStrip;
    u32 m_hostWidth = 0, m_stripWidth = 0, m_loopWidth = 1;
    u32 m_scrollOff = 0, m_scrollCnt = 0;
};

/* 中继服务器行:双排布局(上=服务器名,下=服务器地址),行高与原
 * ListItem 等高(70)。右侧三列「在线 / 房间 / 延迟」:标签在上排、数值在下排,
 * 三列各自居中对齐成一条竖排(去掉了选中服务器的 * 标记 —— 选中状态只由
 * 名字的高亮色表示)。
 * 按 A/触摸 = 切换服务器,按 X = 删除。 */
class ServerRow : public tsl::elm::Element {
public:
    static constexpr u16 kHeight = kMonitorListRowHeight;

    /* 右侧三列的宽度(像素):三列等宽等距,使「延迟与房间」的间距同「在线与房间」完全一致。 */
    static constexpr s32 kOnlineCol = 36;
    static constexpr s32 kRoomCol = 36;
    static constexpr s32 kLatencyCol = 36;
    static constexpr s32 kColGap = 6;
    static constexpr s32 kRightMargin = 20;

    void setServer(u32 index, const char *name, const char *addr) {
        m_index = index;
        snprintf(m_name, sizeof(m_name), "%s", name);
        snprintf(m_addr, sizeof(m_addr), "%s", addr);
    }
    void setSelected(bool sel) {
        m_selected = sel;
        if (!sel)
            m_note[0] = 0;      /* 错误提示只属于刚操作的那一行 */
    }
    /* 三列数值(NULL/空 = "--")。 */
    void setStats(const char *online, const char *rooms, const char *latency) {
        snprintf(m_online, sizeof(m_online), "%s", online && online[0] ? online : "--");
        snprintf(m_rooms, sizeof(m_rooms), "%s", rooms && rooms[0] ? rooms : "--");
        snprintf(m_latency, sizeof(m_latency), "%s", latency && latency[0] ? latency : "--");
        m_latencyKnown = latency && latency[0] && strcmp(latency, "--") != 0;
    }
    /* 切换/删除失败的提示:临时占用下排数值区,下一帧统计刷新时清掉。 */
    void setNote(const char *text) {
        snprintf(m_note, sizeof(m_note), "%s", text ? text : "");
        m_noteFrames = text && text[0] ? 120 : 0;   /* 约 2 秒后自动消失 */
    }
    void clearNote() { m_note[0] = 0; }
    bool hasNote() const { return m_note[0] != 0; }
    bool selected() const { return m_selected; }
    const char* addr() const { return m_addr; }
    /* 名字故意不用 setClickListener:基类 Element 有个同名虚函数
       (std::function<bool(u64)>),重载会触发 -Woverloaded-virtual。 */
    void setActivateListener(std::function<void()> fn) { m_click = std::move(fn); }
    void setDeleteListener(std::function<void()> fn) { m_delete = std::move(fn); }

    virtual void layout(u16, u16, u16, u16) override {
        this->setBoundaries(this->getX(), this->getY(), this->getWidth(), kHeight);
    }

    virtual void draw(tsl::gfx::Renderer *renderer) override {
        using R = tsl::gfx::Renderer;
        renderer->drawRect(this->getX(), this->getY(), this->getWidth(), 1,
                           R::a(tsl::style::color::ColorFrame));

        /* 三列:标签与数值同一字号、各自在列内水平居中 */
        constexpr float kStatFont = 15;
        const s32 latCx = this->getX() + this->getWidth() - kRightMargin - kLatencyCol / 2;
        const s32 roomCx = latCx - kLatencyCol / 2 - kColGap - kRoomCol / 2;
        const s32 onlCx = roomCx - kRoomCol / 2 - kColGap - kOnlineCol / 2;

        /* 服务器名/地址:默认完整显示;只有会伸进右侧统计列时才截断加省略号。 */
        s32 avail = (onlCx - kOnlineCol / 2) - (this->getX() + 20) - 10;
        if (avail < 60)
            avail = 60;     /* 窄屏兜底,别把名字挤成空串 */
        auto fit = [&](const char *s, float fs) -> std::string {
            auto [w, h] = renderer->drawString(s, false, 0, 0, fs,
                                               R::a(tsl::style::color::ColorTransparent));
            if ((s32)w <= avail)
                return s;
            return renderer->limitStringLength(s, false, fs, avail);
        };
        std::string name = fit(m_name, 22);
        renderer->drawString(name.c_str(), false, this->getX() + 20,
                             this->getY() + 32, 22,
                             R::a(m_selected ? tsl::style::color::ColorHighlight
                                             : tsl::style::color::ColorText));
        std::string addr = fit(m_addr, 16);
        renderer->drawString(addr.c_str(), false, this->getX() + 20,
                             this->getY() + 58, 16,
                             R::a(tsl::style::color::ColorDescription));

        auto centerDraw = [&](const char *text, s32 cx, s32 y, tsl::Color color) {
            auto [w, h] = renderer->drawString(text, false, 0, 0, kStatFont,
                                               R::a(tsl::style::color::ColorTransparent));
            renderer->drawString(text, false, cx - (s32)w / 2, y, kStatFont,
                                 R::a(color));
        };
        /* 上排:列名;下排:数值(同字号、同行内居中排列) */
        centerDraw(T("在线", "線上"), onlCx, this->getY() + 30,
                   tsl::style::color::ColorDescription);
        centerDraw(T("房间", "房間"), roomCx, this->getY() + 30,
                   tsl::style::color::ColorDescription);
        centerDraw(T("延迟", "延遲"), latCx, this->getY() + 30,
                   tsl::style::color::ColorDescription);

        if (m_note[0]) {
            centerDraw(m_note, latCx, this->getY() + 58,
                       tsl::style::color::ColorDescription);
            if (m_noteFrames > 0 && --m_noteFrames == 0)
                m_note[0] = 0;
            return;
        }
        centerDraw(m_online, onlCx, this->getY() + 58,
                   tsl::style::color::ColorText);
        centerDraw(m_rooms, roomCx, this->getY() + 58,
                   tsl::style::color::ColorText);
        centerDraw(m_latency, latCx, this->getY() + 58,
                   m_latencyKnown ? tsl::style::color::ColorHighlight
                                  : tsl::style::color::ColorDescription);
    }

    virtual tsl::elm::Element *requestFocus(tsl::elm::Element *oldFocus,
                                            tsl::FocusDirection direction) override {
        return this;
    }

    virtual bool onClick(u64 keys) override {
        if (keys & HidNpadButton_A) {
            if (m_click)
                m_click();
            this->triggerClickAnimation();
            return true;
        }
        if (keys & HidNpadButton_X) {
            if (m_delete)
                m_delete();
            this->triggerClickAnimation();
            return true;
        }
        return false;
    }

    virtual bool onTouch(tsl::elm::TouchEvent event, s32 currX, s32 currY,
                         s32 prevX, s32 prevY, s32 initialX, s32 initialY) override {
        if (event == tsl::elm::TouchEvent::Touch)
            m_touched = this->inBounds(currX, currY);
        if (event == tsl::elm::TouchEvent::Release && m_touched) {
            m_touched = false;
            if (tsl::elm::Element::getInputMode() == tsl::InputMode::Touch)
                return this->onClick(HidNpadButton_A);
        }
        return false;
    }

private:
    u32 m_index = 0;
    char m_name[32] = {};
    char m_addr[80] = {};  // up to 63-byte host + colon + 5-digit port
    char m_online[12] = {};      /* 在线人数 */
    char m_rooms[12] = {};       /* 房间数 */
    char m_latency[16] = {};     /* 延迟文本,如 "38ms" / "--" */
    char m_note[32] = {};        /* 切换/删除失败提示(临时占用数值行) */
    u32 m_noteFrames = 0;        /* 提示还要显示多少帧 */
    bool m_latencyKnown = false;
    bool m_selected = false;
    bool m_touched = false;
    std::function<void()> m_click;
    std::function<void()> m_delete;
};

/* 帧:整帧自己画,不调用 libtesla 的 OverlayFrame::draw()。
 *
 * 原因:
 * 1) 去除标题「联机插件」下方的「阿东版 · xxxx」副标题以及这一整行区域,
 *    内容区上移紧接标题下方(kContentY = 75)。
 * 2) OverlayFrame::draw() 对空 subtitle 调用 drawString("") 时会越过 '\0'
 *    读出未初始化内存造成乱码;直接由 MonitorFrame 接管绘制可彻底避免。
 * 3) 用 setPixel(而非 drawRect 的 setPixelBlendDst 叠加 alpha)恢复头尾背景,
 *    既裁掉列表滚动时的越界像素,又不会在标题下方或底部叠出纯黑条块。 */
class MonitorFrame : public tsl::elm::OverlayFrame {
public:
    static constexpr u16 kContentY = 75;
    static constexpr u16 kTitleBaseline = 50;
    static constexpr float kTitleFont = 30;

    explicit MonitorFrame(const std::string &title)
        : tsl::elm::OverlayFrame(title, std::string()) {}

    virtual void draw(tsl::gfx::Renderer *renderer) override {
        using R = tsl::gfx::Renderer;
        { static bool once = false; if (!once) { once = true; MonitorLog("first-frame"); } }

        const tsl::Color bg = R::a(tsl::style::color::ColorFrameBackground);
        renderer->fillScreen(bg);

        if (this->m_contentElement != nullptr)
            this->m_contentElement->frame(renderer);

        /* 抹除列表滚动越界到顶栏/底栏的像素:用 setPixel 直接写底色,
           避免 drawRect(setPixelBlendDst)把 0xD 半透明底色叠成 0xF 纯黑。 */
        for (s32 y = 0; y < (s32)kContentY - 5; y++) {
            for (s32 x = 0; x < (s32)tsl::cfg::FramebufferWidth - 1; x++)
                renderer->setPixel(x, y, bg);
        }
        for (s32 y = (s32)tsl::cfg::FramebufferHeight - 73;
             y < (s32)tsl::cfg::FramebufferHeight; y++) {
            for (s32 x = 0; x < (s32)tsl::cfg::FramebufferWidth - 1; x++)
                renderer->setPixel(x, y, bg);
        }

        renderer->drawRect(tsl::cfg::FramebufferWidth - 1, 0, 1,
                           tsl::cfg::FramebufferHeight, R::a(0xF222));

        /* 标题 */
        renderer->drawString(this->m_title.c_str(), false, 20, kTitleBaseline,
                             kTitleFont, R::a(tsl::style::color::ColorText));

        /* 底部分隔线 + 本地化按键提示(盖掉 libtesla 的英文 Back/OK) */
        renderer->drawRect(15, tsl::cfg::FramebufferHeight - 73,
                           tsl::cfg::FramebufferWidth - 30, 1,
                           R::a(tsl::style::color::ColorText));
        renderer->drawString(T("\uE0E1  返回     \uE0E0  确定",
                               "\uE0E1  返回     \uE0E0  確定"),
                             false, 30, 693, 23,
                             R::a(tsl::style::color::ColorText));
    }

    /* 内容区上移:标题下面不再留给副标题行。 */
    virtual void layout(u16 parentX, u16 parentY, u16 parentWidth,
                        u16 parentHeight) override {
        this->setBoundaries(parentX, parentY, parentWidth, parentHeight);
        if (this->m_contentElement != nullptr) {
            this->m_contentElement->setBoundaries(parentX + 35, parentY + kContentY,
                                                  parentWidth - 85,
                                                  parentHeight - 73 - kContentY);
            this->m_contentElement->invalidate();
        }
    }
};

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
}

/* (重)建“游戏房间”区块的行。快照 version 变化时由 update() 调用。
   行是持久池(只增不删):不用的行 height=0,焦点永远不会挂在已删除
   元素上;有效房间行固定为 70px,快照变化时更新标题与玩家名。 */
static void rebuildRoomSection(const MonitorSnapshot &snap)
{
    if (!g_list || !g_roomHeader || g_roomHeaderIndex < 0)
        return;

    char header[80];
    if (snap.server[0])
        snprintf(header, sizeof(header), "%s · %s", T("游戏房间", "遊戲房間"), snap.server);
    else
        snprintf(header, sizeof(header), "%s", T("游戏房间", "遊戲房間"));
    g_roomHeader->setText(header);

    u32 need = snap.roomN > 0 ? snap.roomN : 1;   /* 0 房间时用 1 行提示 */
    while (g_roomRows.size() < need) {
        auto *row = new RoomRow();
        g_roomRows.push_back(row);
        g_list->addItem(row, 0, g_roomHeaderIndex + 1 + (int)g_roomRows.size() - 1);
    }

    for (u32 i = 0; i < g_roomRows.size(); i++) {
        if (snap.roomN == 0) {
            if (i == 0) {
                const char *msg;
                if (snap.busy)
                    msg = T("正在查询…", "正在查詢…");
                else if (snap.status[0])
                    msg = snap.status;
                else
                    msg = T("暂无房间", "暫無房間");
                g_roomRows[i]->setHint(msg);
            } else {
                g_roomRows[i]->clearRow();
            }
        } else if (i < snap.roomN) {
            g_roomRows[i]->setRoom(snap.rooms[i]);
        } else {
            g_roomRows[i]->clearRow();
        }
    }
    g_list->invalidate();
}

/* 把每台服务器自己的在线/房间/延迟刷到列表行上。
 *
 * 以前只有选中的那一行有数值(因为只有它连着中继);现在后台线程会轮转
 * 探测每台服务器(MonitorListServerStats),没测过的先显示 "--",测到之后
 * 自动出现数字 —— 不需要先选中它。
 *
 * static 缓冲:MonitorServerStat × 32 ≈ 3.7KB,不放栈上(见 draw 注释)。 */
static void refreshServerRowStats(const MonitorSnapshot &snap)
{
    static MonitorServerStat stats[MONITOR_MAX_SERVERS];

    u32 n = MonitorListServerStats(stats, MONITOR_MAX_SERVERS);

    char onlineBuf[16], roomsBuf[16], latBuf[16];
    for (size_t k = 0; k < g_serverRows.size(); k++) {
        ServerRow *row = g_serverRows[k];
        /* 按 addr 匹配,避免 g_serverRows(按 ldnMitm 索引)与
           stats(按 relay.cfg 顺序)顺序不一致导致数据错位 */
        const MonitorServerStat *st = nullptr;
        for (u32 i = 0; i < n; i++) {
            if (strcmp(stats[i].addr, row->addr()) == 0) {
                st = &stats[i];
                break;
            }
        }
        if (st == nullptr && !row->selected()) {
            row->setStats(nullptr, nullptr, nullptr);
            continue;
        }
        /* 在线/房间:选中的服务器优先用监视器快照(刚查过),否则用后台探测值 */
        s32 online = st ? st->online : -1;
        s32 rooms = st ? st->rooms : -1;
        if (row->selected()) {
            if (snap.online >= 0)
                online = snap.online;
            if (snap.roomCount >= 0)
                rooms = snap.roomCount;
        }
        if (online >= 0)
            snprintf(onlineBuf, sizeof(onlineBuf), "%d", (int)online);
        else
            snprintf(onlineBuf, sizeof(onlineBuf), "--");
        if (rooms >= 0)
            snprintf(roomsBuf, sizeof(roomsBuf), "%d", (int)rooms);
        else
            snprintf(roomsBuf, sizeof(roomsBuf), "--");

        /* 延迟:所有服务器(含选中服)在每轮刷新周期中通过同一套 5 字节 UDP PING
           同步测量写入 st->latencyMs;尚未测出时退回 sysmodule 测量值 */
        s32 lat = st ? st->latencyMs : 0;
        if (row->selected() && lat <= 0) {
            u32 ms = 0;
            if (R_SUCCEEDED(ldnMitmGetRelayLatency(&g_ldnConfig, &ms)) && ms > 0)
                lat = (s32)ms;
        }
        if (lat > 0)
            snprintf(latBuf, sizeof(latBuf), lat > 999 ? ">999ms" : "%dms", (int)lat);
        else
            snprintf(latBuf, sizeof(latBuf), "--");

        if (!row->hasNote())
            row->setStats(onlineBuf, roomsBuf, latBuf);
    }
}

class MainGui : public tsl::Gui {
public:
    MainGui() { }
    virtual ~MainGui() {
        /* libtesla 默认 CloseOnExit=true,按 B 退出根页面时 goBack() 直接调用
         * close() 而不触发 onHide();这里在析构时立即置暂停标志,让后台线程在
         * 进入 exitServices()->MonitorExit() 前就中断阻塞查询。 */
        g_visible = false;
        MonitorSetPaused(true);
    }

    virtual tsl::elm::Element* createUI() override {
        MonitorLog("ui-begin");
        // This overlay ships inside a Chinese integration package and the
        // bundled font has CJK glyphs, so the UI is localised in place.
        // 标题下面不再显示「阿东版 · 版本号」副标题(整行区域已删除),
        // 版本号仍保留在列表底部的「关于」区块里。
        auto frame = new MonitorFrame(T("联机插件", "連線插件"));

        g_list = new RebuildList();
        buildList(g_list);

        frame->setContent(g_list);

        // 新建的行右侧还是空的("--/--/--")。强制第一次 update() 就把三列
        // 画出来:数值缓存没失效时 update() 会提前返回,行上就一直空着。
        invalidateServerStats();
        // 同理:强制首次重建游戏房间区块。
        g_monitorVersion = 0xFFFFFFFFu;

        MonitorLog("ui-ready");
        return frame;
    }

    // Called once every frame to update values
    virtual void update() override {
        // Coming back from the add page: the relay list changed while this
        // Gui sat underneath it, so rebuild now that it is on top again.
        if (g_main_list_dirty) {
            g_main_list_dirty = false;
            rebuildUi();
            focusAfterRebuild(g_addServerItem);
        }

        // Put the cursor back on the row the user was on before the list was
        // rebuilt (delete / restore). Runs before draw, so the target is only
        // found once List::draw() has inserted the freshly built rows.
        if (g_focus_after_rebuild != nullptr) {
            if (g_list != nullptr) {
                const s32 idx = g_list->getIndexInList(g_focus_after_rebuild);
                if (idx >= 0) {
                    g_list->setFocusedIndex(static_cast<u32>(idx));
                    g_list->snapToFocus();
                    this->requestFocus(g_focus_after_rebuild, tsl::FocusDirection::None);
                    g_focus_after_rebuild = nullptr;
                } else if (--g_focus_retries <= 0) {
                    g_focus_after_rebuild = nullptr;
                }
            } else {
                g_focus_after_rebuild = nullptr;
            }
        }

        // Cancel an armed "restore defaults" if the user moved the cursor
        // away, so the row never stays in a half-confirmed state.
        if (g_restoreArmed && g_restoreItem != nullptr &&
            this->getFocusedElement() != g_restoreItem) {
            g_restoreArmed = false;
            g_restoreItem->setValue("");
        }


        // 游戏房间区块:监视器快照 version 变化时重建行,并在同一帧同步刷新全部服务器行的统计。
        static MonitorSnapshot snap;   /* 8.6KB:static,别放栈上(见 draw 注释) */
        MonitorCopySnapshot(&snap);
        if (snap.version != g_monitorVersion) {
            g_monitorVersion = snap.version;
            rebuildRoomSection(snap);
            invalidateServerStats();
            if (g_visible && g_state == State::Loaded && !g_serverRows.empty()) {
                refreshServerRowStats(snap);
                g_lastStatsNs = armTicksToNs(armGetSystemTick());
            }
        }

        // 所有服务器的在线/房间/延迟每 1 秒与当前选中服务器同步批量刷新一轮。
        if (g_visible && g_state == State::Loaded) {
            u64 nowNs = armTicksToNs(armGetSystemTick());
            if (g_lastPollNs == 0)
                g_lastPollNs = nowNs;
            if (nowNs - g_lastPollNs >= 1000000000ull) {
                g_lastPollNs = nowNs;
                MonitorRequestPoll();
            }
        }
        // 服务器行右侧三列「在线 / 房间 / 延迟」兜底定时刷新。
        if (g_visible && g_state == State::Loaded && !g_serverRows.empty()) {
            u64 nowNs = armTicksToNs(armGetSystemTick());
            if (g_lastStatsNs == 0 || nowNs - g_lastStatsNs >= 500000000ull) {
                g_lastStatsNs = nowNs;
                refreshServerRowStats(snap);
            }
        }
    }

    // Called once every frame to handle inputs not handled by other UI elements
    virtual bool handleInput(u64 keysDown, u64 keysHeld, const HidTouchState &touchPos,
                             HidAnalogStickState joyStickPosLeft,
                             HidAnalogStickState joyStickPosRight) override {
        if (keysDown & HidNpadButton_B) {
            /* 按 B 返回特斯拉菜单时第一时间通知后台中断网络等待 */
            g_visible = false;
            MonitorSetPaused(true);
        }
        return false;
    }
};

/* Preset picker. libtesla has no text input (Tesla cannot open swkbd from a
   LibraryApplet), so "add" means putting one of the factory relays back.
   Entries that are already configured say 已添加 and do nothing. */
class AddServerGui : public tsl::Gui {
public:
    virtual tsl::elm::Element* createUI() override {
        u32 builtin = 0;
        if (R_FAILED(ldnMitmGetBuiltinRelayServerCount(&g_ldnConfig, &builtin))) {
            builtin = 0;
        }
        u32 current = 0;
        ldnMitmGetRelayServerCount(&g_ldnConfig, &current);

        // The subtitle carries the capacity state: the list is capped at
        // LDN_MAX_SERVERS, so backups can only be added after freeing a slot.
        char subtitle[96];
        if (current >= LDN_MAX_SERVERS) {
            snprintf(subtitle, sizeof(subtitle),
                     T("已满 %u/%u · 先删一台再用备选", "已滿 %u/%u · 先刪一台再用備選"),
                     static_cast<unsigned>(current), static_cast<unsigned>(LDN_MAX_SERVERS));
        } else {
            snprintf(subtitle, sizeof(subtitle),
                     T("内置 %u 台 · 当前 %u/%u", "內建 %u 台 · 目前 %u/%u"),
                     static_cast<unsigned>(builtin), static_cast<unsigned>(current),
                     static_cast<unsigned>(LDN_MAX_SERVERS));
        }
        auto frame = new tsl::elm::OverlayFrame(T("添加服务器", "新增伺服器"), subtitle);
        auto *list = new tsl::elm::List();

        list->addItem(new tsl::elm::CategoryHeader(T("内置服务器（按 A 添加）", "內建伺服器（按 A 新增）")));

        for (u32 i = 0; i < builtin; i++) {
            LdnRelayServerInfo info = {};
            if (R_FAILED(ldnMitmGetBuiltinRelayServerInfo(&g_ldnConfig, i, &info))) {
                continue;
            }
            bool present = false;
            for (u32 k = 0; k < current; k++) {
                LdnRelayServerInfo cur = {};
                if (R_SUCCEEDED(ldnMitmGetRelayServerInfo(&g_ldnConfig, k, &cur)) &&
                    strcmp(cur.host, info.host) == 0 && cur.port == info.port) {
                    present = true;
                    break;
                }
            }

            /* Do not paint host:port here. libtesla's ListItem does not
               truncate the value, and a long address (e.g.
               muitxobem-lanplay.ddns.net:11451) is wider than the row, so it
               was drawn on top of the left-hand name. A short status word
               keeps the name readable; the addresses live in the README. */
            auto *item = new tsl::elm::ListItem(info.name);
            item->setValue(present ? T("已添加", "已新增") : T("可添加", "可新增"), present);

            auto added = std::make_shared<bool>(present);
            auto count = std::make_shared<u32>(current);
            item->setClickListener([item, info, added, count](u64 keys) {
                if (!(keys & HidNpadButton_A)) {
                    return false;
                }
                if (*added) {
                    return true;
                }
                if (*count >= LDN_MAX_SERVERS) {
                    item->setValue(T("先删一台", "先刪一台"), true);
                    return true;
                }
                if (R_SUCCEEDED(ldnMitmAddRelayServer(&g_ldnConfig, &info))) {
                    *added = true;
                    (*count)++;
                    item->setValue(T("已添加", "已新增"), true);
                    g_main_list_dirty = true;
                } else {
                    item->setValue(T("添加失败", "新增失敗"), true);
                }
                return true;
            });
            list->addItem(item);
        }

        frame->setContent(list);
        return frame;
    }
};


/* Keep the monitor target aligned with the sysmodule's selected relay after
   deleting the selected row or restoring the factory list. */
static void syncMonitorTargetFromRelaySelection() {
    u32 count = 0;
    u32 selected = 0;
    if (R_FAILED(ldnMitmGetRelayServerCount(&g_ldnConfig, &count)) || count == 0 ||
        R_FAILED(ldnMitmGetSelectedRelayServer(&g_ldnConfig, &selected)) || selected >= count) {
        g_selectedName[0] = 0;
        MonitorRequestSwitch(nullptr);
        return;
    }
    char name[32] = {};
    if (R_FAILED(ldnMitmGetRelayServerName(&g_ldnConfig, selected, name))) {
        g_selectedName[0] = 0;
        MonitorRequestSwitch(nullptr);
        return;
    }
    snprintf(g_selectedName, sizeof(g_selectedName), "%s", name);
    MonitorRequestSwitch(g_selectedName);
}

/* Everything below the frame header. Kept out of createUI() so it can be
   called again after the relay list changes: libtesla cannot refresh a
   single row, but it can delete and re-add the whole list on the next
   frame (List::clear() + addItem() are both deferred). */
static void buildList(tsl::elm::List *list) {
    g_serverRows.clear();
    g_roomRows.clear();
    g_roomHeader = nullptr;
    g_roomHeaderIndex = -1;
    g_monitorVersion = 0xFFFFFFFFu;
    g_selectedName[0] = 0;
    g_restoreItem = nullptr;
    g_addServerItem = nullptr;
    g_restoreArmed = false;

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

        /* Patch 10's monitor header stays above the relay selector. Rows are
           inserted directly after it by rebuildRoomSection(). */
        g_roomHeaderIndex = 5;  // 3 toggles + 2 internet-relay entries
        g_roomHeader = new tsl::elm::CategoryHeader(T("游戏房间", "遊戲房間"));
        list->addItem(g_roomHeader);
        list->addItem(new tsl::elm::CategoryHeader(
            T("中继服务器（按 A 切换，按 X 删除）", "中繼伺服器（按 A 切換，按 X 刪除）")));

        u32 count = 0;
        if (R_FAILED(ldnMitmGetRelayServerCount(&g_ldnConfig, &count))) {
            list->addItem(new tsl::elm::ListItem(T("读取服务器列表失败", "讀取伺服器清單失敗")));
        } else if (count == 0) {
            list->addItem(new tsl::elm::ListItem(T("没有服务器，请恢复默认", "沒有伺服器，請恢復預設")));
        } else {
            u32 selected = 0;
            if (R_FAILED(ldnMitmGetSelectedRelayServer(&g_ldnConfig, &selected))) {
                selected = count;
            }
            static MonitorServer monServers[MONITOR_MAX_SERVERS];
            u32 monCount = 0;
            for (u32 i = 0; i < count; i++) {
                LdnRelayServerInfo info = {};
                char name[32] = {};
                char addr[80] = {};
                if (R_SUCCEEDED(ldnMitmGetRelayServerInfo(&g_ldnConfig, i, &info))) {
                    snprintf(name, sizeof(name), "%s", info.name);
                    if (info.host[0]) {
                        snprintf(addr, sizeof(addr), "%s:%u", info.host,
                                 static_cast<unsigned>(info.port));
                    }
                } else {
                    ldnMitmGetRelayServerName(&g_ldnConfig, i, name);
                }

                if (addr[0] && monCount < MONITOR_MAX_SERVERS) {
                    snprintf(monServers[monCount].name, sizeof(monServers[monCount].name),
                             "%.31s", name);
                    snprintf(monServers[monCount].addr, sizeof(monServers[monCount].addr),
                             "%.63s", addr);
                    monCount++;
                }

                auto *row = new ServerRow();
                row->setServer(i, name, addr);
                row->setSelected(i == selected);
                if (i == selected)
                    snprintf(g_selectedName, sizeof(g_selectedName), "%s", name);

                row->setActivateListener([i, name = std::string(name), row]() {
                    if (R_FAILED(ldnMitmSetSelectedRelayServer(&g_ldnConfig, i))) {
                        row->setNote(T("切换失败", "切換失敗"));
                        return;
                    }
                    for (size_t k = 0; k < g_serverRows.size(); k++)
                        g_serverRows[k]->setSelected(k == i);
                    invalidateServerStats();
                    snprintf(g_selectedName, sizeof(g_selectedName), "%s", name.c_str());
                    MonitorRequestSwitch(g_selectedName);
                });

                row->setDeleteListener([i, row]() {
                    if (R_SUCCEEDED(ldnMitmDeleteRelayServer(&g_ldnConfig, i))) {
                        syncMonitorTargetFromRelaySelection();
                        rebuildUi();
                        if (!g_serverRows.empty()) {
                            const size_t next = (i < g_serverRows.size()) ? i : (g_serverRows.size() - 1);
                            focusAfterRebuild(g_serverRows[next]);
                        } else {
                            focusAfterRebuild(g_restoreItem);
                        }
                    } else {
                        row->setNote(T("删除失败", "刪除失敗"));
                    }
                });

                g_serverRows.push_back(row);
                list->addItem(row);
            }
            MonitorSetServerList(monServers, monCount);
        }

        // Undo a mistake without editing relay.cfg on a PC. Two presses on
        // purpose: this rewrites the whole relay list.
        list->addItem(new tsl::elm::CategoryHeader(T("管理", "管理")));

        g_addServerItem = new tsl::elm::ListItem(T("添加服务器", "新增伺服器"));
        g_addServerItem->setClickListener([](u64 keys) {
            if (keys & HidNpadButton_A) {
                tsl::changeTo<AddServerGui>();
                return true;
            }
            return false;
        });
        list->addItem(g_addServerItem);

        g_restoreItem = new tsl::elm::ListItem(T("恢复默认服务器", "恢復預設伺服器"));
        g_restoreItem->setClickListener([](u64 keys) {
            if (!(keys & HidNpadButton_A)) {
                return false;
            }
            if (!g_restoreArmed) {
                g_restoreArmed = true;
                g_restoreItem->setValue(T("再按 A 确认", "再按 A 確認"), true);
                return true;
            }
            g_restoreArmed = false;
            if (R_SUCCEEDED(ldnMitmRestoreDefaultRelayServers(&g_ldnConfig))) {
                syncMonitorTargetFromRelaySelection();
                rebuildUi();
                focusAfterRebuild(g_restoreItem);
            } else if (g_restoreItem != nullptr) {
                g_restoreItem->setValue(T("恢复失败", "恢復失敗"), true);
            }
            return true;
        });
        list->addItem(g_restoreItem);

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

    // Rebuilt rows start as "-- / -- / --"; force update() to paint them.
    invalidateServerStats();
}

/* Rebuild the visible list after the relay list changed. The old rows are
   deleted by List::draw() on the next frame, so focus is dropped first:
   leaving the Gui pointing at a deleted element would crash on the next
   input. restoreFocus() makes the following frame pick a fresh row. */
static void rebuildUi() {
    if (g_list == nullptr) {
        return;
    }
    auto &gui = tsl::Overlay::get()->getCurrentGui();
    if (gui == nullptr) {
        return;
    }
    gui->removeFocus();
    g_list->clear();
    buildList(g_list);
    gui->restoreFocus();
}

class Overlay : public tsl::Overlay {
public:
    virtual void initServices() override {
        g_state = State::Uninit;
        detectLanguage();
        MonitorSetTraditional(g_isTraditional);
        tsl::hlp::doWithSmSession([&] {
            Result rc;

            /* bsd socket 由监视器在首次网络查询时按需初始化(见 monitor.cpp
               EnsureSockets):把缓冲分配挪出 initScreen 的帧缓冲关键窗口,
               避免 ovlloader 小堆上 0x559;失败(无网络)只影响查询不影响设置。 */

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

        /* 版本串仍要兜底:tagless 构建显示 commit 短哈希,服务调用失败时
           显示「版本未知」,免得「关于」里那一行是空的。 */
        if (g_version[0] == '\0')
            snprintf(g_version, sizeof(g_version), "%s", T("版本未知", "版本未知"));

        MonitorInitSockets();   /* 自带 sm 包裹;放在 initScreen 帧缓冲之前,堆最宽裕 */
        MonitorInit();
        MonitorLog("initServices-done");
    }
    virtual void exitServices() override {
        MonitorExit();          /* 内部负责 socketExit(延迟初始化的 socket) */
        serviceClose(&g_ldnConfig.s);
        serviceClose(&g_ldnSrv);
    }

    virtual void onShow() override {
        // 每次点开 Tesla 插件立即刷新在线/房间。
        g_visible = true;
        g_lastPollNs = 0;
        MonitorSetPaused(false);
        MonitorRequestRefresh(g_selectedName[0] ? g_selectedName : nullptr);
    }
    virtual void onHide() override {
        g_visible = false;
        // 让后台立刻放弃正在进行的下载/查询:返回特斯拉菜单时不该再去
        // 抢 CPU 或阻塞线程退出。
        MonitorSetPaused(true);
    }    // Called before overlay wants to change from visible to invisible state

    virtual std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<MainGui>();  // Initial Gui to load. It's possible to pass arguments to it's constructor like this
    }
};

int main(int argc, char **argv) {
    return tsl::loop<Overlay>(argc, argv);
}
