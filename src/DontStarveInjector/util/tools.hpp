#pragma once
#include <memory>
template<typename Fn>
auto create_defer(Fn&& fn) {
    auto deleter = [cb = std::forward<Fn>(fn)](void *) {
        cb();
    };
    return std::unique_ptr<void, decltype(deleter)>(nullptr, std::move(deleter));
}