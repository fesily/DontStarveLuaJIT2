
#include "Progress.hpp"
#include <thread>
#include <format>
#include <atomic>
#include <string>
#include <utility>
#include <windows.h>
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")

#define ID_PROGRESS 1001
#define ID_TIMER 1002
#define ID_STATUS_TEXT 1003
static struct {
    int max_step;
    int cur;
    HWND hwnd;
    HWND hProgress;
    HWND hStatusText;
    std::atomic_bool ready;
    Generator<int>* gen;
} progress_ctx;

// 窗口过程函数
LRESULT CALLBACK ProgressWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {

    switch (uMsg) {
        case WM_CREATE: {
            RECT rect;
            GetClientRect(hwnd, &rect);
            int clientWidth = rect.right - rect.left;
            int clientHeight = rect.bottom - rect.top;

            // 计算进度条位置和大小
            int progressX = clientWidth * 0.05;     // 5% 边距
            int progressY = clientHeight * 0.1;     // 10% 边距
            int progressWidth = clientWidth * 0.9;  // 90% 宽度
            int progressHeight = clientHeight * 0.3;// 30% 高度

            // 计算文本控件位置和大小
            int textX = progressX;
            int textY = progressY + progressHeight + 10;// 进度条下方 10 像素
            int textWidth = progressWidth;
            int textHeight = clientHeight * 0.2;// 20% 高度

            // 在窗口创建时初始化进度条
            progress_ctx.hProgress = CreateWindowEx(
                    0, PROGRESS_CLASS, NULL,
                    WS_CHILD | WS_VISIBLE | PBS_SMOOTH,// PBS_SMOOTH 使进度条平滑
                    10, 10, 300, 20,                   // 位置和大小
                    hwnd, (HMENU) ID_PROGRESS,
                    GetModuleHandle(NULL), NULL);
            // 设置进度条范围和初始位置
            SendMessage(progress_ctx.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, progress_ctx.max_step));
            SendMessage(progress_ctx.hProgress, PBM_SETPOS, 0, 0);
            // 创建静态文本控件
            progress_ctx.hStatusText = CreateWindowEx(
                    0, "STATIC", "0%",
                    WS_CHILD | WS_VISIBLE | SS_CENTER,
                    10, 40, 300, 20,// 位置: x=10, y=40, 宽=300, 高=20（进度条下方）
                    hwnd, (HMENU) ID_STATUS_TEXT,
                    GetModuleHandle(NULL), NULL);
            SetTimer(hwnd, ID_TIMER, 20, NULL);
            progress_ctx.ready = true;
            return 0;
        }
        case WM_TIMER: {
            if (wParam == ID_TIMER) {
                if (progress_ctx.gen) {
                    if (*progress_ctx.gen) {
                        (*progress_ctx.gen)(); 
                    } else  {
                        KillTimer(hwnd, ID_TIMER);
                        PostMessage(hwnd, WM_CLOSE, 0, 0); // 进度完成，关闭窗口
                    }
                }
            }
            return 0;
        }
        case WM_DESTROY: {
            // 窗口销毁时退出消息循环
            PostQuitMessage(0);
            return 0;
        }
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

void ShowProgressWindow(int maxstep, Generator<int>& gen) {
    progress_ctx.max_step = maxstep;
    progress_ctx.cur = 0;
    progress_ctx.gen = &gen;
    // 注册窗口类
    WNDCLASS wc = {0};
    wc.lpfnWndProc = ProgressWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "ProgressWindowClass";
    RegisterClass(&wc);

    // 创建窗口
    HWND hwnd = CreateWindowEx(
            0, "ProgressWindowClass", "patch process...",
            WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_MINIMIZEBOX,// 禁用最大化和最小化按钮
            CW_USEDEFAULT, CW_USEDEFAULT, 400, 100,
            NULL, NULL, GetModuleHandle(NULL), NULL);

    // 显示窗口
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    // 模态消息循环
    MSG msg;
    while (GetMessage(&msg, hwnd, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        if (progress_ctx.ready) {
            if (gen) {
                gen();
            } else {
                break;
             }
        }
    }
    DestroyWindow(hwnd);
}

void set_progress(int step, const std::string_view& msg) {
    if (!progress_ctx.ready) return;

    if (step > 0) {
        progress_ctx.cur += step;
        SendMessage(progress_ctx.hProgress, PBM_SETPOS, progress_ctx.cur, 0);
        if (progress_ctx.cur >= progress_ctx.max_step) {// 进度达到 100% 时关闭窗口
            PostMessage(progress_ctx.hwnd, WM_CLOSE, 0, 0);
        }
    }
    if (!msg.empty()) {
        std::string statusText = std::format("{:.1f} % [{}]", progress_ctx.cur / (float)progress_ctx.max_step * 100, msg);
        SetWindowText(progress_ctx.hStatusText, statusText.c_str());
    }
}