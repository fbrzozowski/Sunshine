/**
 * @file src/platform/windows/interception_helper.h
 * @brief Dynamic loading wrapper for the Interception driver (keyboard only).
 * @details The Interception driver (https://github.com/oblitum/Interception) sends input
 * at the driver level, bypassing the LLKHF_INJECTED flag that Windows kernel adds
 * to keystrokes injected via SendInput(). This is important for games and anti-cheats
 * that detect injected input.
 *
 * Architecture:
 * - Keyboard: Uses set_filter() + passthrough thread. The filter activates the driver's
 *   write path for send(). The passthrough thread receives physical keystrokes intercepted
 *   by the filter and immediately re-sends them so they aren't swallowed.
 * - Mouse: NOT handled here. Setting a mouse filter causes feedback loops where injected
 *   events are re-captured, causing cursor snapping and jitter.
 */
#pragma once

// platform includes
#include <Windows.h>

// standard includes
#include <atomic>
#include <string_view>
#include <thread>

// local includes
#include "src/logging.h"

namespace interception {
  using namespace std::literals;

  // Minimal Interception API type definitions (from interception.h)
  constexpr int IC_MAX_KEYBOARD = 10;
  constexpr int IC_KEYBOARD(int index) {
    return (index) + 1;
  }

  // Key state flags
  constexpr unsigned short IC_KEY_DOWN = 0x00;
  constexpr unsigned short IC_KEY_UP = 0x01;
  constexpr unsigned short IC_KEY_E0 = 0x02;
  constexpr unsigned short IC_KEY_E1 = 0x04;

  // Filter
  constexpr unsigned short IC_FILTER_KEY_ALL = 0xFFFF;

  // Stroke structures
  struct ICKeyStroke {
    unsigned short code;
    unsigned short state;
    unsigned int information;
  };

  // Generic stroke (sized to the largest stroke type for receive/send)
  struct ICMouseStroke {
    unsigned short state;
    unsigned short flags;
    short rolling;
    int x;
    int y;
    unsigned int information;
  };

  union ICStroke {
    ICKeyStroke key;
    ICMouseStroke mouse;
  };

  // Function pointer typedefs
  using fn_create_context_t = void *(*)();
  using fn_destroy_context_t = void (*)(void *);
  using fn_set_filter_t = void (*)(void *, int (*)(int), unsigned short);
  using fn_send_t = int (*)(void *, int, const void *, unsigned int);
  using fn_receive_t = int (*)(void *, int, void *, unsigned int);
  using fn_wait_with_timeout_t = int (*)(void *, unsigned long);
  using fn_is_keyboard_t = int (*)(int);
  using fn_get_hardware_id_t = unsigned int (*)(void *, int, void *, unsigned int);

  struct InterceptionState {
    HMODULE hModule = nullptr;

    // Function pointers
    fn_create_context_t pfn_create_context = nullptr;
    fn_destroy_context_t pfn_destroy_context = nullptr;
    fn_set_filter_t pfn_set_filter = nullptr;
    fn_send_t pfn_send = nullptr;
    fn_receive_t pfn_receive = nullptr;
    fn_wait_with_timeout_t pfn_wait = nullptr;
    fn_is_keyboard_t pfn_is_keyboard = nullptr;
    fn_get_hardware_id_t pfn_get_hardware_id = nullptr;

    // Driver state
    void *ic_ctx = nullptr;
    int ic_keyboard_device = 0;

    // Passthrough thread
    std::thread kbd_passthrough_thread;
    std::atomic<bool> running {false};

    InterceptionState() = default;

    ~InterceptionState() {
      cleanup();
    }

    // Non-copyable
    InterceptionState(const InterceptionState &) = delete;
    InterceptionState &operator=(const InterceptionState &) = delete;

    /**
     * @brief Initialize the Interception driver for keyboard input.
     * @return true if the driver was successfully initialized.
     */
    bool init() {
      hModule = LoadLibraryA("interception.dll");
      if (!hModule) {
        BOOST_LOG(info) << "Interception driver DLL not found. Keyboard will use SendInput."sv;
        return false;
      }

      // Resolve all required function pointers
      pfn_create_context = (fn_create_context_t) GetProcAddress(hModule, "interception_create_context");
      pfn_destroy_context = (fn_destroy_context_t) GetProcAddress(hModule, "interception_destroy_context");
      pfn_set_filter = (fn_set_filter_t) GetProcAddress(hModule, "interception_set_filter");
      pfn_send = (fn_send_t) GetProcAddress(hModule, "interception_send");
      pfn_receive = (fn_receive_t) GetProcAddress(hModule, "interception_receive");
      pfn_wait = (fn_wait_with_timeout_t) GetProcAddress(hModule, "interception_wait_with_timeout");
      pfn_is_keyboard = (fn_is_keyboard_t) GetProcAddress(hModule, "interception_is_keyboard");
      pfn_get_hardware_id = (fn_get_hardware_id_t) GetProcAddress(hModule, "interception_get_hardware_id");

      if (!pfn_create_context || !pfn_destroy_context || !pfn_set_filter ||
          !pfn_send || !pfn_receive || !pfn_wait || !pfn_is_keyboard || !pfn_get_hardware_id) {
        BOOST_LOG(warning) << "Failed to resolve Interception API functions"sv;
        cleanup();
        return false;
      }

      // Create driver context
      ic_ctx = pfn_create_context();
      if (!ic_ctx) {
        BOOST_LOG(warning) << "Failed to create Interception context"sv;
        cleanup();
        return false;
      }

      // Find the first valid keyboard device
      wchar_t hw_id[256];
      for (int i = 0; i < IC_MAX_KEYBOARD; ++i) {
        int device = IC_KEYBOARD(i);
        auto len = pfn_get_hardware_id(ic_ctx, device, hw_id, sizeof(hw_id));
        if (len > 0) {
          ic_keyboard_device = device;
          BOOST_LOG(info) << "Interception: found keyboard device " << device << " (index " << i << ")"sv;
          break;
        }
      }

      if (!ic_keyboard_device) {
        BOOST_LOG(warning) << "Interception: no keyboard devices found"sv;
        cleanup();
        return false;
      }

      // Set keyboard filter — this activates the driver's write path for send()
      // Without this filter, send() calls for keyboard would be silently ignored
      pfn_set_filter(ic_ctx, pfn_is_keyboard, IC_FILTER_KEY_ALL);

      // Start passthrough thread to forward physical keystrokes that the filter intercepts
      running.store(true);
      kbd_passthrough_thread = std::thread(&InterceptionState::kbd_passthrough_loop, this);

      BOOST_LOG(info) << "Interception driver initialized for keyboard (device " << ic_keyboard_device << ")"sv;
      return true;
    }

    /**
     * @brief Send a keyboard scancode via the Interception driver.
     * @param scancode The keyboard scancode.
     * @param extended Whether this is an extended key (E0 prefix).
     * @param release Whether this is a key release event.
     * @return true if the keystroke was sent successfully.
     */
    bool send_keyboard(unsigned short scancode, bool extended, bool release) {
      if (!ic_ctx || !ic_keyboard_device || !pfn_send) {
        return false;
      }

      ICKeyStroke stroke {};
      stroke.code = scancode;
      stroke.state = release ? IC_KEY_UP : IC_KEY_DOWN;
      if (extended) {
        stroke.state |= IC_KEY_E0;
      }
      stroke.information = 0;

      return pfn_send(ic_ctx, ic_keyboard_device, &stroke, 1) > 0;
    }

    /**
     * @brief Clean up all Interception resources.
     */
    void cleanup() {
      // Signal the passthrough thread to stop
      running.store(false);

      if (kbd_passthrough_thread.joinable()) {
        kbd_passthrough_thread.join();
      }

      if (ic_ctx && pfn_destroy_context) {
        pfn_destroy_context(ic_ctx);
        ic_ctx = nullptr;
      }

      ic_keyboard_device = 0;

      if (hModule) {
        FreeLibrary(hModule);
        hModule = nullptr;
      }
    }

  private:
    /**
     * @brief Passthrough loop that receives and re-sends physical keystrokes.
     * @details When a keyboard filter is active, the Interception driver intercepts
     * all physical keyboard input. This thread immediately re-sends those keystrokes
     * so the physical keyboard continues to work normally.
     */
    void kbd_passthrough_loop() {
      ICStroke stroke {};

      while (running.load()) {
        // Wait for a keystroke with a timeout so we can check the running flag
        int device = pfn_wait(ic_ctx, 50);
        if (device <= 0) {
          continue;  // Timeout or error
        }

        // Only process keyboard devices
        if (!pfn_is_keyboard(device)) {
          continue;
        }

        // Receive and immediately re-send the physical keystroke
        if (pfn_receive(ic_ctx, device, &stroke, 1) > 0) {
          pfn_send(ic_ctx, device, &stroke, 1);
        }
      }
    }
  };

}  // namespace interception
