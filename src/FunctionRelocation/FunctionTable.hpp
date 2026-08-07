#pragma once

#include "export.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace function_relocation {

// Half-open [start, end) span in image VA space (image_base + RVA).
// Nucleus Function::end is exclusive (BB end is first byte past last insn).
struct FunctionSpan {
  uint64_t start = 0; // entry / function start VA
  uint64_t end = 0;   // exclusive end VA
};

// Sorted table of function spans with binary-search containing queries.
class FUNCTION_RELOCATION_API FunctionTable {
public:
  void clear() { spans_.clear(); }

  // Keep sorted by start. Invalid / empty spans are ignored.
  // Overlaps are allowed but preferred not to occur; lookup still uses
  // the rightmost span whose start <= addr.
  void add(FunctionSpan span) {
    if (span.end <= span.start) {
      return;
    }
    auto it = std::lower_bound(
        spans_.begin(), spans_.end(), span,
        [](const FunctionSpan &a, const FunctionSpan &b) {
          return a.start < b.start;
        });
    spans_.insert(it, span);
  }

  // Returns start of function containing addr, or 0 if none.
  uint64_t containing(uint64_t addr) const {
    const FunctionSpan *s = span_containing(addr);
    return s ? s->start : 0;
  }

  const FunctionSpan *span_containing(uint64_t addr) const {
    if (spans_.empty()) {
      return nullptr;
    }
    auto it = std::upper_bound(
        spans_.begin(), spans_.end(), addr,
        [](uint64_t a, const FunctionSpan &s) { return a < s.start; });
    if (it == spans_.begin()) {
      return nullptr;
    }
    --it;
    if (addr >= it->start && addr < it->end) {
      return &*it;
    }
    return nullptr;
  }

  const std::vector<FunctionSpan> &spans() const { return spans_; }
  bool empty() const { return spans_.empty(); }
  size_t size() const { return spans_.size(); }

private:
  std::vector<FunctionSpan> spans_; // sorted by start
};

} // namespace function_relocation
