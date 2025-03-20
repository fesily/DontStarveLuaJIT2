#pragma once
#include <string_view>
#include <coroutine>
#include <exception>

template<typename T>
struct Generator
{
    // 类名 'Generator' 只是我们的选择，使用协程魔法不依赖它。
    // 编译器通过关键词 'co_yield' 的存在识别协程。
    // 你可以使用 'MyGenerator'（或者任何别的名字）作为替代，只要在类中包括了
    // 拥有 'MyGenerator get_return_object()' 方法的嵌套 struct promise_type。
    // （注意：在重命名时，你还需要调整构造函数/析构函数的声明。）
 
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;
 
    struct promise_type // 必要
    {
        T value_;
        std::exception_ptr exception_;
 
        Generator get_return_object()
        {
            return Generator(handle_type::from_promise(*this));
        }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void unhandled_exception() { exception_ = std::current_exception(); } // 保存异常
 
        template <std::convertible_to<T> From> // C++20 概念
        std::suspend_always yield_value(From&& from)
        {
            value_ = std::forward<From>(from); // 在承诺中缓存结果
            return {};
        }
        void return_void() {}
    };
 
    handle_type h_;
 
    Generator(handle_type h) : h_(h) {}
    ~Generator() { h_.destroy(); }
    explicit operator bool()
    {
        fill(); // 获知协程是结束了还是仍能通过 C++ getter（下文的 operator()）
                // 获得下一个生成值的唯一可靠方式，是执行/恢复协程到下一个 co_yield 节点
                // （或让执行流抵达结尾）。
                // 我们在承诺中存储/缓存了执行结果，使得 getter（下文的 operator()）
                // 可以获得这一结果而不执行协程。
        return !h_.done();
    }
    T operator()()
    {
        fill();
        full_ = false;// 我们将移动走先前缓存的结果来重新置空承诺
        return std::move(h_.promise().value_);
    }
 
private:
    bool full_ = false;
 
    void fill()
    {
        if (!full_)
        {
            h_();
            if (h_.promise().exception_)
                std::rethrow_exception(h_.promise().exception_);
            // 在调用上下文中传播协程异常
 
            full_ = true;
        }
    }
};
#define NoShowProgressWindow(_, gen) for(;gen;) { gen(); }

#ifdef SUPPORT_PROGRESS
void ShowProgressWindow(int maxstep, Generator<int>& gen);
void set_progress(int step, const std::string_view& msg);
#else
#define ShowProgressWindow(_, gen) NoShowProgressWindow(_, gen)
#define set_progress(...)
#endif
