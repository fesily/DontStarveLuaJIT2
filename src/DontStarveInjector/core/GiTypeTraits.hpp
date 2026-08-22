#pragma once
// Map C++ function pointer types → GiType[ret, args...] for service / GameInjector registration.

#include "GameInjectorLuaRegistry.hpp"

#include <cstddef>
#include <cstdint>
#include <type_traits>

struct lua_State;
struct NetSimStats;

namespace ds::plugin {
namespace detail {

template <class T>
struct GiMap;

template <> struct GiMap<void> { static constexpr GiType value = GiType::Void; };
template <> struct GiMap<bool> { static constexpr GiType value = GiType::Bool; };
template <> struct GiMap<char> { static constexpr GiType value = GiType::I8; };
template <> struct GiMap<signed char> { static constexpr GiType value = GiType::I8; };
template <> struct GiMap<unsigned char> { static constexpr GiType value = GiType::I8; };
template <> struct GiMap<short> { static constexpr GiType value = GiType::I32; };
template <> struct GiMap<int> { static constexpr GiType value = GiType::I32; };
template <> struct GiMap<unsigned int> { static constexpr GiType value = GiType::U32; };
template <> struct GiMap<unsigned long> { static constexpr GiType value = GiType::U32; };
template <> struct GiMap<long> { static constexpr GiType value = GiType::I32; };
template <> struct GiMap<long long> { static constexpr GiType value = GiType::I64; };
template <> struct GiMap<unsigned long long> { static constexpr GiType value = GiType::I64; };
template <> struct GiMap<float> { static constexpr GiType value = GiType::F32; };
template <> struct GiMap<double> { static constexpr GiType value = GiType::F64; };
template <> struct GiMap<const char *> { static constexpr GiType value = GiType::CString; };
template <> struct GiMap<char *> { static constexpr GiType value = GiType::CString; };
template <> struct GiMap<const int *> { static constexpr GiType value = GiType::OptI32; };
template <> struct GiMap<const NetSimStats *> { static constexpr GiType value = GiType::NetSimStats; };
template <> struct GiMap<NetSimStats *> { static constexpr GiType value = GiType::NetSimStats; };

template <class T>
struct GiMap<T *> {
    static constexpr GiType value = GiType::LightUserdata;
};
template <class T>
struct GiMap<T &> {
    static constexpr GiType value = GiType::LightUserdata;
};

template <class T>
struct GiMap<const T> : GiMap<T> {};
template <class T>
struct GiMap<volatile T> : GiMap<T> {};

template <class Fn>
struct GiFnSig;

template <>
struct GiFnSig<int (*)(lua_State *)> {
    static constexpr GiType types[] = {GiType::LuaCFunction};
    static constexpr size_t ntypes = 1;
};

template <class R, class... Args>
struct GiFnSig<R (*)(Args...)> {
    static constexpr GiType types[] = {GiMap<std::remove_cv_t<R>>::value,
                                       GiMap<std::remove_cv_t<Args>>::value...};
    static constexpr size_t ntypes = 1 + sizeof...(Args);
    static_assert(ntypes <= kGiMaxTypes, "function arity exceeds kGiMaxTypes");
};

#if defined(__cpp_noexcept_function_type)
template <class R, class... Args>
struct GiFnSig<R (*)(Args...) noexcept> : GiFnSig<R (*)(Args...)> {};
#endif

template <class Fn>
struct GiFnSigDecay {
    using Raw = std::decay_t<Fn>;
    using Ptr = std::conditional_t<std::is_function_v<Raw>, Raw *, Raw>;
    using type = GiFnSig<Ptr>;
};

} // namespace detail

template <class Fn>
using GiSignature = typename detail::GiFnSigDecay<Fn>::type;

} // namespace ds::plugin
