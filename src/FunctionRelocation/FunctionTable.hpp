#pragma once

#include "export.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace function_relocation {

// Half-open [start, end) span in process VA space (image_base + RVA).
// `end` is exclusive.
struct FunctionSpan {
  uint64_t start = 0; // entry / function start VA
  uint64_t end = 0;   // exclusive end VA
};

// Code owned by a function whose primary body starts elsewhere: PE .pdata
// chained records (cold paths, SEH funclets, separated code). `owner` is the
// primary entry VA. owner == 0 marks an orphan fragment — it only blocks
// scanning and never names an entry.
struct FunctionFragment {
  FunctionSpan span{};
  uint64_t owner = 0;
};

// Sorted table of function spans with binary-search containing queries.
// `spans()` is the primary (contiguous, non-overlapping) entry set; fragments
// are consulted only by `containing()`, never by `span_containing()`.
class FUNCTION_RELOCATION_API FunctionTable {
public:
  void clear() {
    spans_.clear();
    fragments_.clear();
    laminar_.reset();
  }

  // Keep sorted by start. Invalid / empty spans are ignored.
  // Overlaps / nesting are allowed; lookup picks the tightest container.
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

  // Bulk load: one sort instead of N sorted inserts (discovery feeds tens of
  // thousands of spans, where insert-per-span is quadratic).
  // Same start keeps the longest end; identical fragments are deduped.
  void assign(std::vector<FunctionSpan> spans,
              std::vector<FunctionFragment> fragments = {}) {
    laminar_.reset();
    spans.erase(std::remove_if(spans.begin(), spans.end(),
                               [](const FunctionSpan &s) { return s.end <= s.start; }),
                spans.end());
    std::sort(spans.begin(), spans.end(),
              [](const FunctionSpan &a, const FunctionSpan &b) {
                return a.start < b.start || (a.start == b.start && a.end < b.end);
              });
    std::vector<FunctionSpan> primaries;
    primaries.reserve(spans.size());
    for (const auto &span: spans) {
      if (!primaries.empty() && primaries.back().start == span.start) {
        primaries.back().end = (std::max)(primaries.back().end, span.end);
        continue;
      }
      primaries.push_back(span);
    }
    spans_ = std::move(primaries);

    fragments.erase(std::remove_if(fragments.begin(), fragments.end(),
                                   [](const FunctionFragment &f) {
                                     return f.span.end <= f.span.start;
                                   }),
                    fragments.end());
    std::sort(fragments.begin(), fragments.end(),
              [](const FunctionFragment &a, const FunctionFragment &b) {
                return a.span.start < b.span.start ||
                       (a.span.start == b.span.start && a.span.end < b.span.end);
              });
    fragments.erase(std::unique(fragments.begin(), fragments.end(),
                                [](const FunctionFragment &a, const FunctionFragment &b) {
                                  return a.span.start == b.span.start &&
                                         a.span.end == b.span.end && a.owner == b.owner;
                                }),
                    fragments.end());
    fragments_ = std::move(fragments);
  }

  // Returns start of the function owning addr: the tightest primary container,
  // otherwise the owner of the containing cold fragment (0 when orphan).
  uint64_t containing(uint64_t addr) const {
    if (const FunctionSpan *s = span_containing(addr)) {
      return s->start;
    }
    if (fragments_.empty()) {
      return 0;
    }
    auto it = std::upper_bound(
        fragments_.begin(), fragments_.end(), addr,
        [](uint64_t value, const FunctionFragment &f) { return value < f.span.start; });
    // Walking back from the last fragment start <= addr: the first fragment
    // that still reaches addr owns the byte (fragments are disjoint).
    while (it != fragments_.begin()) {
      --it;
      if (addr < it->span.end) {
        return it->owner;
      }
    }
    return 0;
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
    // An exact entry always wins, even when an enclosing span also covers it.
    if (it != spans_.begin()) {
      const auto previous = std::prev(it);
      if (previous->start == addr) {
        return &*previous;
      }
    }
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
  const std::vector<FunctionFragment> &fragments() const { return fragments_; }
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
    // Stack of the ends of the currently enclosing spans. A span is allowed
    // either completely inside the innermost encloser (nested) or after it
    // (disjoint); crossing its end means arbitrary overlap.
    bool laminar = true;
    std::vector<uint64_t> enclosing;
    for (const auto &span: spans_) {
      while (!enclosing.empty() && span.start >= enclosing.back()) {
        enclosing.pop_back();
      }
      if (!enclosing.empty() && span.end > enclosing.back()) {
        laminar = false;
        break;
      }
      enclosing.push_back(span.end);
    }
    laminar_ = laminar;
    return laminar;
  }

  std::vector<FunctionSpan> spans_;         // primary entries, sorted by start
  std::vector<FunctionFragment> fragments_; // cold fragments, sorted by start
  mutable std::optional<bool> laminar_;
};

} // namespace function_relocation
