---
name: deploy-gguf-vlm-llama-cpp-windows
description: 在 Windows 本机用 llama.cpp CUDA 构建部署 HuggingFace GGUF（含视觉 mmproj）模型并作为常驻服务验证（下载→校验→启动→多模态冒烟→排障）
---

# 在 Windows 上用 llama.cpp 部署 GGUF（含 VLM）

适用：本机 `C:\Users\fesil\llama-cuda`（CUDA 13 打包，自带运行时）部署 HF 上的 GGUF/多模态模型，`C:\Users\fesil\models\<name>\` 存放模型。

## 0. 前置事实核查（不要猜）
- 用 HF API 列文件与体积：`https://huggingface.co/api/models/<repo>/tree/main`（每文件含 `lfs.oid`=sha256 与 `size`）；模型卡用 `/raw/main/README.md`。
- 确认本地构建支持该 arch：在 `llama.dll` / `mtmd.dll` 里搜二进制字符串（如 `qwen35`、`minicpmv`、`siglip`）。CUDA 设备与算力：`llama-cli.exe --list-devices`（会打印 compute capability）。
- 默认卸载行为看 `--help`：本构建 `-ngl` 默认 `auto`（`--fit` 默认 on），即有 GPU 就自动占满。

## 1. 选择量化
- ≤1B 模型（如 MiniCPM-V 4.6 = Qwen3.5-0.8B + SigLIP2-400M）：Q8_0 + `mmproj-model-f16.gguf`，约 1.9 GB，8 GB 卡全量卸载。
- 下载用**一个**后台 job 顺序 `curl -sL -o`；不要 `mkdir & curl ... & wait` 并行（第二个 curl 会先于 mkdir 执行而丢文件）。

## 2. 校验
- 按 `lfs.oid` 比对 sha256 + 精确字节数；不一致就别启动。

## 3. 启动（本机约束）
- bash 工具**无法**按绝对路径执行 exe；统一用
  `powershell -NoProfile -Command "& 'C:\...\llama-server.exe' -m '...gguf' --mmproj '...gguf' -c 16384 -ngl all --reasoning off --host 127.0.0.1 --port 8080"`
  并以服务方式托管（name + ready port + 之后设 `proc://<id>/mode` = persist）。
- 服务 ready 只测端口会“假就绪”：加载期 `/health` 返回 503，需轮询 `/health` 到 `{"status":"ok"}` 再冒烟。
- 思考模型默认开关由 llama.cpp 决定：模板里 `enable_thinking` 未定义时会被覆写为 on；要默认不思考加 `--reasoning off`（instruct 模型对齐上游 v4.6 的 vLLM 配方），单请求再开用 `"chat_template_kwargs": {"enable_thinking": true}`。

## 4. 冒烟（必须有）
- 先看渲染后的提示：`POST /apply-template {"messages":[{"role":"user","content":"Say hi"}]}`，确认 `assistant` 后是否带 ` thinking`。
- CLI：`llama-mtmd-cli.exe -m ... --mmproj ... --image x.png -p "..."`（注意该 CLI 无 `-st`）。
- API：`POST /v1/chat/completions`，图片用 base64 data URI。造图用 PIL + arialbd.ttf（含明确文字+形状便于判分）。
- 记录：先用例延迟/用量、`nvidia-smi --query-compute-apps` 确认 llama-server 是 compute app、显存占用。

## 5. 交付脚本
- `start-server.bat` 必须 **CRLF**（`write` 工具给的是 LF，cmd 会拆坏 `^` 续行，症状：`'m' 不是内部或外部命令`）→ 用 python 以 `\r\n` 写字节。
- README.md 写清：文件+sha256、启动/停止、端点、curl 示例、思考开关、调参、实测数字；不要声称未验证的能力（如无 WebUI 就说 415）。

## 6. 排障速查
- `exit 1` 且 Application 日志无崩溃记录、日志戛然而止 → 查 System 日志 `Resource-Exhaustion-Detector` 事件 2004（commit 耗尽）。本机提交上限≈物理 93.7 GB + 页文件 22.8 GB；常与大内存进程（dontstarve 专用服、vmmemWSL）冲突。
- GGUF 加载报 `invalid ggml type N` → 构建过旧/该量化过新（如 type 43 = MXFP8）。
- 本构建 `GET /` → 415 = 无内置 WebUI。
