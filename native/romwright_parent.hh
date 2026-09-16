// Managed consoles must not survive an abruptly terminated importing process.
#ifndef ROMWRIGHT_PARENT_HH
#define ROMWRIGHT_PARENT_HH

#if defined(__unix__)
#include <chrono>
#include <climits>
#include <cstdlib>
#include <thread>
#include <unistd.h>

inline void romwrightWatchParent() {
  const char *text = std::getenv("ROMWRIGHT_PARENT_PID");
  if (text == nullptr) return; // Standalone interactive console.
  char *end = nullptr;
  const unsigned long value = std::strtoul(text, &end, 10);
  if (end == text || *end != '\0' || value <= 1 || value > INT_MAX)
    std::_Exit(125);
  const pid_t parent = static_cast<pid_t>(value);
  // PR_SET_PDEATHSIG follows the spawning thread, not the process. Console
  // sessions can outlive a Rust shard-creation thread, so observe the process.
  std::thread([parent] {
    while (::getppid() == parent)
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::_Exit(125);
  }).detach();
}
#endif
#endif
