#pragma once

#include "export.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
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
  void clear() {
    spans_.clear();
    laminar_.reset();
  }

  // Keep sorted by start. Invalid / empty spans are ignored.
  // Overlaps / nesting are allowed (Nucleus may emit a large outer body that
  // wholly contains later entry-points). Lookup picks the tightest container.
  void add(FunctionSpan span) {
    if (span.end <= span.start) {
      return;
    }
    laminar_.reset();
    auto it = std::lower_bound(
        spans_.begin(), spans_.end(), span,
        [](const FunctionSpan &a, const FunctionSpan &b) {
          return a.start < b.start;
        });
    spans_.insert(it, span);
  }

  // Bulk load: one sort instead of N sorted inserts (apply_nucleus_function_table
  // feeds ~4e5 spans, where insert-per-span is quadratic).
  void assign(std::vector<FunctionSpan> spans) {
    laminar_.reset();
    spans.erase(std::remove_if(spans.begin(), spans.end(),
                               [](const FunctionSpan &s) { return s.end <= s.start; }),
                spans.end());
    std::sort(spans.begin(), spans.end(),
              [](const FunctionSpan &a, const FunctionSpan &b) { return a.start < b.start; });
    spans_ = std::move(spans);
  }

  // Refine spans so every known entry VA that falls strictly inside a parent
  // becomes a sub-span start: [S, e0), [e0, e1), …, [en, End).
  // Used for PE SYM_TYPE_FUNC exports and module-known function addresses so
  // interior exports (e.g. lua_resume inside a lua_yield outer body) map
  // containing(E) → E instead of the outer start.
  // Does not hardcode symbol names — any address list works.
  void split_at_known_entries(const std::vector<uint64_t> &entries) {
    if (spans_.empty() || entries.empty()) {
      return;
    }
    std::vector<uint64_t> pts = entries;
    std::sort(pts.begin(), pts.end());
    pts.erase(std::unique(pts.begin(), pts.end()), pts.end());

    std::vector<FunctionSpan> out;
    out.reserve(spans_.size() + pts.size());
    for (const auto &sp : spans_) {
      std::vector<uint64_t> cuts;
      for (uint64_t e : pts) {
        if (e > sp.start && e < sp.end) {
          cuts.push_back(e);
        }
      }
      if (cuts.empty()) {
        out.push_back(sp);
        continue;
      }
      uint64_t cur = sp.start;
      for (uint64_t c : cuts) {
        if (c > cur) {
          out.push_back(FunctionSpan{cur, c});
        }
        cur = c;
      }
      if (sp.end > cur) {
        out.push_back(FunctionSpan{cur, sp.end});
      }
    }
    std::sort(out.begin(), out.end(),
              [](const FunctionSpan &a, const FunctionSpan &b) {
                return a.start < b.start;
              });
    spans_ = std::move(out);
    laminar_.reset();
  }

  // Returns start of the tightest (innermost) function containing addr, or 0.
  uint64_t containing(uint64_t addr) const {
    const FunctionSpan *s = span_containing(addr);
    return s ? s->start : 0;
  }

  // Prefer the smallest containing span (deepest nest). Ties keep the rightmost
  // start so later nested entries win over large outer parents.
  // Spans form a laminar family (nested or disjoint) in practice, so walking
  // back from the last start <= addr and stopping at the first span that still
  // reaches addr yields the tightest container. The old full walk visited every
  // earlier span (~4e5) on each query, which dominated short-body matching.
  const FunctionSpan *span_containing(uint64_t addr) const {
    if (spans_.empty()) {
      return nullptr;
    }
    // First span with start > addr.
    auto it = std::upper_bound(
        spans_.begin(), spans_.end(), addr,
        [](uint64_t a, const FunctionSpan &s) { return a < s.start; });
    if (is_laminar()) {
      // Nested or disjoint: walking back from the last start <= addr, the first
      // span that still reaches addr is the innermost (tightest) one.
      while (it != spans_.begin()) {
        --it;
        if (addr < it->end) {
          return &*it;
        }
      }
      return nullptr;
    }
    // Arbitrary overlaps: keep the original tightest-wins rule.
    const FunctionSpan *best = nullptr;
    while (it != spans_.begin()) {
      --it;
      if (addr >= it->start && addr < it->end) {
        if (!best || (it->end - it->start) < (best->end - best->start) ||
            ((it->end - it->start) == (best->end - best->start) &&
             it->start > best->start)) {
          best = &*it;
        }
      }
    }
    return best;
  }

  const std::vector<FunctionSpan> &spans() const { return spans_; }
  bool empty() const { return spans_.empty(); }
  size_t size() const { return spans_.size(); }

private:
  // Cached "spans form a laminar family" test (nested or disjoint). The fast
  // containment walk is only valid then; otherwise the exact tightest-wins scan
  // runs. Reset by every mutator.
  bool is_laminar() const {
    if (laminar_) {
      return *laminar_;
    }
    uint64_t max_end = 0;
    bool laminar = true;
    for (const auto &span: spans_) {
      if (span.start < max_end && span.end > max_end) {
        laminar = false;
        break;
      }
      max_end = (std::max)(max_end, span.end);
    }
    laminar_ = laminar;
    return laminar;
  }

  std::vector<FunctionSpan> spans_; // sorted by start
  mutable std::optional<bool> laminar_;
};

} // namespace function_relocation
