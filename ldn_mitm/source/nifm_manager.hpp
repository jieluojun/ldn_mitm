#pragma once
#include <stratosphere.hpp>

namespace ams::mitm::ldn {

    /* nifm:a allows only two sessions system-wide; hold one only while needed. */
    class NifmSessionManager {
        private:
            static os::SdkMutex g_mutex;
            static int g_refcount;
        public:
            static Result Acquire();
            static void Release();
            /* Tear the nifm session down and bring it back up without touching
               the reference count. Needed by the relay reconnect path: a plain
               reopen only swaps the socket, and because another component also
               holds a reference, nifmExit() never ran and the stale internet
               connection request survived. */
            static Result ForceReinit();
    };

    class ScopedNifmSession {
        private:
            Result rc;
        public:
            ScopedNifmSession() : rc(NifmSessionManager::Acquire()) {}
            ScopedNifmSession(const ScopedNifmSession &) = delete;
            ScopedNifmSession &operator=(const ScopedNifmSession &) = delete;
            ~ScopedNifmSession() {
                if (R_SUCCEEDED(rc)) {
                    NifmSessionManager::Release();
                }
            }
            Result GetResult() const { return rc; }
    };

}
