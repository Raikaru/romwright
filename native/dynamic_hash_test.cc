#include "dynamic.hh"
#include <iostream>

int main() {
  using ghidra::DynamicHash;
  using ghidra::uint4;
  using ghidra::uint8;
  const uint8 base = 0x8001a537abcdef01ULL;
  for (uint4 total : {1U, 8U, 9U, 16U, 128U}) {
    for (uint4 position = 0; position < total; ++position) {
      uint8 encoded = DynamicHash::withTotalPosition(base, position, total);
      if (DynamicHash::getPositionFromHash(encoded) != position ||
          DynamicHash::getTotalFromHash(encoded) != total)
        return 1;
      if (total <= 8 && encoded != (base | ((uint8)position << 49) |
                                             ((uint8)(total - 1) << 52)))
        return 2;
      DynamicHash::clearTotalPosition(encoded);
      if (encoded != base)
        return 3;
    }
  }
  for (auto invalid : {std::make_pair(0U, 0U), std::make_pair(0U, 129U),
                       std::make_pair(8U, 8U)}) {
    try {
      DynamicHash::withTotalPosition(base, invalid.first, invalid.second);
      return 4;
    } catch (const ghidra::LowlevelError &) {
    }
  }
  std::cout << "dynamic hash collision identity: passed\n";
}
