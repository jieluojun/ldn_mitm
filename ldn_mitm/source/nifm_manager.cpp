#include "nifm_manager.hpp"
#include "debug.hpp"

namespace ams::mitm::ldn {

    os::SdkMutex NifmSessionManager::g_mutex;
    int NifmSessionManager::g_refcount = 0;

    Result NifmSessionManager::Acquire() {
        std::scoped_lock lk(g_mutex);

        if (g_refcount == 0) {
            Result rc = nifmInitialize(NifmServiceType_Admin);
            if (R_FAILED(rc)) {
                LogFormat("NifmSessionManager: nifmInitialize failed: %x", rc);
                return rc;
            }
            LogFormat("NifmSessionManager: session acquired");
        }

        g_refcount++;
        R_SUCCEED();
    }

    void NifmSessionManager::Release() {
        std::scoped_lock lk(g_mutex);

        if (g_refcount <= 0) {
            LogFormat("NifmSessionManager: unbalanced Release (refcount %d)", g_refcount);
            return;
        }

        g_refcount--;

        if (g_refcount == 0) {
            nifmExit();
            LogFormat("NifmSessionManager: session released");
        }
    }

    Result NifmSessionManager::ForceReinit() {
        std::scoped_lock lk(g_mutex);

        if (g_refcount <= 0) {
            /* Nothing holds it, so a plain initialise is equivalent. */
            g_refcount = 1;
            Result rc = nifmInitialize(NifmServiceType_Admin);
            if (R_FAILED(rc)) {
                g_refcount = 0;
                LogFormat("NifmSessionManager: forced reinit failed to init: %x", rc);
                return rc;
            }
            LogFormat("NifmSessionManager: session acquired (forced)");
            R_SUCCEED();
        }

        /* Any outstanding nifmRequest must already be closed by the caller; it
           dies with the session. Keep the reference count intact so the other
           holders' Release() calls still balance out. */
        nifmExit();
        const Result rc = nifmInitialize(NifmServiceType_Admin);
        LogFormat("NifmSessionManager: forced reinit %s (%x, refcount %d)",
                  R_SUCCEEDED(rc) ? "ok" : "failed", rc, g_refcount);
        return rc;
    }

}
