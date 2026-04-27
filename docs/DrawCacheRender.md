DrawCacheRender 渲染流程（7 阶段）
Phase 1 — 帧选择
- 调用 sAnim::GetFrame(playMode, time) 得到 sFrame*，null 则退出
Phase 2 — 变换矩阵
- CalculateScaleMatrix 计算世界变换 × 缩放矩阵
- 三分支：普通 / 全 billboard / 圆柱 billboard
Phase 3 — 全局 Shader 设置（每节点一次）
- 侵蚀贴图绑定（slot 0）、纹理状态/过滤
- AddColour/MultColour → RGBA 解包 → AutoShaderConstant
- 根据 haunted flag + effectOverride 选择 shader
- SetBlendMode / SetDepthBias / SetVertexDescription
Phase 4 — Pass 循环（1~2 次）
- Pass 0：stencil mask write（关闭 color/depth write）
- Pass 1：正常 color 绘制
- 每 pass 应用旋转矩阵、上传 model matrix 常量
Phase 5 — 隐藏层/符号预处理
- 遍历 sFrame::numObjects，为 override 槽（TDC+0xD8..0xF7）匹配元素索引
Phase 6 — 元素内循环（核心）
for each sAnimElement in pFrame:
  GetOverrideBuildForSymbol(symbolHash, buildFrame) → (pBuild, pSBSF)
  ApplyTextures(pBuild) if pBuild changed
  elemFinal = passMatrix * elemAffine(m_a/b/c/d/m_tx/m_ty)
  upload as AutoShaderConstant
  if vbHandle2 valid: Draw(vertexStart2, vertexCount2)
  if vbHandle  valid: Draw(vertexStart, vertexCount)
- Draw order：secondary VB（bloom underlay）先画，primary 后画
Phase 7 — 清理
- 恢复 depth func、stencil func、color write
- 销毁 6 个 AutoShaderConstant RAII 对象