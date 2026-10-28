# Rust 安全抽象与 unsafe Rust 生态：2026 年 8–10 月变化报告

## 摘要

本报告是《Rust 安全抽象与 unsafe Rust 生态全景调研》（时效锚点 2026-08-02）的增量跟踪，覆盖 **2026-08-02 至 2026-10-27** 的变化。三个月内，**语言语义层没有出现定案级事件**（Tree Borrows 未成为 Miri 默认、#132898 未修复、FLS 首版未发布、SAFETY 注释仍在 Pre-RFC），但**工程与产业层明显加速**：Rust 1.98/1.99 落地多项 unsafe 相关 API 与文档保证，Kani 0.68 的 Autoharness 开始支持泛型函数，verify-rust-std 认可工具增至 5 个（KMIR 于 2026-08-21 由审批转认可），微软自述将 Rust 列为内部 Tier-1 语言（厂商自述、单一来源），欧盟 CRA 漏洞报告义务到期生效。同时，**风险面从"unsafe 代码本身的 UB"扩展到"工具链与供应链"**：arrayref 遭投毒、维护者遭定向社会工程攻击、Miri 环境变量经 CI 缓存泄漏 secrets；tokio 两条公告性质不同：Interval 竞态 UAF 属并发实现缺陷，AsyncFd 安全构造器违反 I/O safety 才是"安全 API 被迫转为 unsafe"的抽象设计教训。

## 1. 跟踪方法与判读规则

本次跟踪以原报告 12 个维度底稿为基线，逐项核查一手来源（Rust 官方博客与 release notes、GitHub 仓库与 Issue、RustSec、LWN、Rust Foundation、Ferrocene 官方文档）。变化分为三类：**已确认变化**（有一手来源与日期）、**无变化（已核实）**（给出核查对象，而非"未听说"）、**口径待标注**（工具能力与挑战完成数不可混用、二手来源降级等）。原报告结尾的 7 项"遗留未决"逐项在第 8 节给出状态。**置信度说明**：除官方博客、release notes、RustSec 公告页等一手来源（高置信）外，gccrs（单一 LWN 报道）、微软 Tier-1（Rust Foundation 客座文章，厂商自述）、DARPA TRACTOR 与 Safety Tags 论文状态（二手或时点较早）均为中/低置信，正文已逐处标注；RustSec 公告、Kani、KMIR、Ferrocene 等日期已于 2026-10-27 回查一手页面；仍无法回查的条目（如 TRACTOR 首份评估报告）已标"日期未核实"或降为背景。

## 2. 语言与编译器：unsafe 相关 API 与文档保证密集落地

### 2.1 Rust 1.98.0（2026-08-20）

1.98.0 稳定了代数浮点方法（`algebraic_add` 等），允许编译器按实数代数性质重排浮点运算，官方明确"非确定但**从不导致 UB**"[^1^]。对 unsafe 生态更直接的有两点：其一，`ManuallyDrop` 与 `Box` 交互的文档保证——1.96.0 起"drop 后再 move `ManuallyDrop<Box<_>>`"不再是 UB，1.98.0 将这一行为写进文档成为**稳定保证**，这类"先把隐式语义变成显式承诺"的动作与 T-opsem 规范化的方向一致（该关联为本报告推断，官方公告未如此表述）[^1^]。其二，lint 层面新增 `invalid_runtime_symbol_definitions`（deny 默认）与 `suspicious_runtime_symbol_definitions`（warn 默认），针对 `memcmp`/`memset`/`strlen` 等 core 运行时符号的错误定义，并新增 `c_void_returns`（warn 默认）检查 `core::ffi::c_void` 作为返回类型——都是 FFI/链接期正确性问题[^2^]（注：[^2^] 所指 stable 页面抓取时已滚动到 1.99，1.98.0 条目以官方博客[^1^]为准）。

### 2.2 Rust 1.98.1（2026-09-03）：安全代码被编译出 UB 的警示

1.98.1 修复了 1.98.0 引入的 vtable 生成 miscompilation：特定情况下 rustc 会在 trait 对象 vtable 中把函数指针生成为空指针，**导致 emitted code 出现未定义行为**[^3^]。官方措辞强调，这不只是段错误，空指针可被用作"任意效果"的正当化依据。该事件与原报告 #132898（优化先于语义）同属编译器正确性问题（成因不同，不宜视为同一风险族）：**Rust 的 soundness 承诺依赖编译器正确性**，因此使用 1.98.0 的项目应视为必须升级项。

### 2.3 Rust 1.99.0（2026-10-01）与 1.99.1

1.99.0 稳定了 `extern "C"` 可变参数函数定义（`VaList`、`VaArgSafe`），Rust 现在可以自己实现 C ABI 的 variadic 函数，官方示例直接展示了 `unsafe extern "C" fn` 与 `// SAFETY:` 注释的配套写法[^4^]。同时稳定了三个裸指针布局查询 API——`Layout::for_value_raw`、`mem::size_of_val_raw`、`mem::align_of_val_raw`，为 sized 与非 sized 类型的裸指针尺寸/对齐查询**定下安全要求**[^4^]。容器与指针互转也显著扩充：`Vec::into_parts/from_parts`、`Box::into_non_null/from_non_null`，为自定义容器的 unsafe 封装提供更规范的出入口。值得注意的是 `Box::leak` 文档更新：官方**劝阻 round-trip unleaking**（leak 后再释放），理由是它与现有及未来优化、以及即将到来的自定义 allocator 稳定化存在不良交互，建议改用 `Box::into_non_null`/`into_raw`——这是一条会影响既有 unsafe 代码评审标准的文档级变化[^4^]。1.99.1（10-15）为点发布；按六周节奏，1.100.0 预计 2026-11-12[^5^]。

### 2.4 借用检查与类型系统：Polonius 与新 trait solver 上 nightly

2026-08-04，下一代借用检查器（Polonius 迭代）在 nightly 默认开启；08-21，下一代 trait solver 也在 nightly 开启[^6^]。二者都属于 2026 项目目标中"Project Zero（修复已知类型系统 soundness bug）"与"稳定化"路线：Polonius Alpha 目标是解决 NLL 遗留的 Problem Case #3 并配套 a-mir-formality 形式化，新 solver 则是替换旧实现、解锁 soundness 修复与 async 特性[^7^]。对 unsafe 生态的含义是间接但重要的：类型系统层的 soundness 债正在被系统性清偿，但其夜间开启也意味着**生态需要一轮回归验证期**，不宜把 nightly 行为当作稳定承诺。

## 3. 语义规范化与别名模型：定案无进展，目标更具体

截至 2026-10 核查，Miri 官方 README 仍然写明：**Stacked Borrows 为默认，Tree Borrows 是可选替代**，且 TB"比 SB 更实验性"，最终别名模型可能比 TB 更严格[^8^]。UCG #573（强化 TB 以废弃 SB）仍 open，没有正式 FCP；`writable` 隐式写之争（#584）本次未核查到决议，状态未知[^9^]。因此原报告"双模型同测"的保守建议**继续有效**。

#132898（ReferencePropagation 把 SB 合法代码优化出 UB）仍 open，但窗口内出现了实质推进：社区先提交保守变体 PR #156896（凡源 place 存在其他间接借用即拒绝折叠），该 PR 已关闭；随后提出**精确 place-overlap gate**（仅当重叠 place 存在其他存活派生指针时拒绝），并附上 rustlantis 1500 seeds 差分模糊、Crater 44 crate、tokio/spotatui 全量构建等验证记录[^10^]。需要谨慎的是，上述验证记录（rustlantis 1500 seeds、Crater 44 crate、tokio/spotatui 构建）均为**提交者自述**，维护者尚未评审，也未见独立复现；PR #156896 的关闭日期底稿未记录。issue 讨论中另有声音称这些方案涉及 agent 辅助生成与披露争议、关闭理由偏向披露而非技术否决，但这仅见于单条 issue 讨论[^10^]，**低置信**；因此应读作"修复路径正在形成（待评审）"，而非"即将合并"。

规范化三线的状态是"目标更清晰、成果未落地"：**FLS** 仓库 README 仍明确其"不是 Rust 的 normative 规范"，未见到 rust-lang 自有首版发布[^11^]；**T-opsem 的 normative unsafe 文档**（2026 目标 #644）则给出了可执行方法——采用 zerocopy 模式（为每个 unsafe 块引用官方文档论证），以 Eclipse iceoryx2 约 3,300 处 unsafe 为试点，预计归纳为约 20 类模式、其中 5–7 类需要新建 normative 文档，重点覆盖跨进程同步、内存映射、跨进程原子操作与共享内存中的 `UnsafeCell`[^12^]。**SAFETY 注释**方面，《Rust Safety Standard》仍在 internals 的 Pre-RFC 讨论中，未进入正式 RFC；学术侧的 Safety Tags RFC 据论文 v2（2026-04）记录已累积 50+ commits 与 170 条评论，Rust-for-Linux 与 Bevy 表达了采用兴趣；但该数据截至 2026-04，不能证明 2026-10 "仍在审阅"，本次未核查 RFC 当前状态（中低置信）[^13^][^14^]。

最后，sanitizer 稳定化取得**渐进但未收官**的进展：ASan/LSan 已接近稳定（总跟踪 issue 为 rust#123615，ASan/LSan 的稳定化实现 PR 为 rust#123617，二者并非同一编号），并新增了一个默认开启 ASan 的 Tier 2 target（rust#149644）使稳定编译器可用；MSan/TSan 仍处 2026 项目目标推进中，未见稳定落地[^15^][^16^]。

## 4. 验证工具：Kani 0.68 直击"泛型缺口"，挑战赛认可工具增至 5 个

Kani 0.68.0 是本窗口内工具层最重磅的发布。除 `#[kani::loop_decreases]`（循环终止性证明）、SARIF 输出与 `--export-json`（便于接入 GitHub Code Scanning）、`no_std` 开箱即用、stub sets 与量词算术/指针算术外，**Autoharness 的扩展直接命中原报告记录的最大缺口**：支持**泛型函数**（含按参数与 trait impl 推导实例化、`Fn` 界类型参数用非确定闭包实例化）、裸指针参数、slice/String/Vec 参数（有界与无界）、编译器可推导 pointee 的智能指针、`--constructor-args` 构造器驱动生成，以及从类型自身断言中挖掘不变量作为值过滤器；harness 默认并行验证[^17^]。工具链升至 nightly-2026-08-21、CBMC 6.11.0；GitHub releases 页显示 0.68.0 发布于 9 月 16 日 03:43（页面未显示年份，据工具链日期按 2026 年理解）。同版本还修复了一批 Kani 自身 soundness 问题（求解器丢弃量词时不再静默通过、f128→i128 下界、OffsetModel 指针回绕等），这与原报告"验证器自身也要被验证"的判断一致[^17^]。**口径提醒**：Autoharness 支持泛型是工具能力落地，不等于 std 挑战中 9,635 个被跳过函数已经解决。

verify-rust-std 挑战赛的变化需分清口径。**认可工具（窗口内变化，高置信）**：基线（2025-10 的 Lessons 论文快照与 2026-03 的仓库数据）记录 4 个已批准工具（Kani、ESBMC/GOTO-Transcoder、VeriFast、Flux），KMIR 与 Creusot、RAPx 同处"审批中"；仓库 README 现称认可工具为 Flux、GOTO Transcoder (ESBMC)、Kani、KMIR、VeriFast，其中 KMIR 的 Tool Application 议题 #296 与 PR #310（"Add kmir tool description and CI workflow"）均于 **2026-08-21** 合并/关闭，即由审批转认可发生在窗口内，工具数 4→5。**挑战解决数（口径提醒）**：仓库总表现为 29 个挑战中 10 个 Resolved（#1、3、5、6、9、11、12、14、15、19），其余 19 个 Open；2025-10 论文快照记为 9 个被接受解，但两处统计口径可能不同，且总表未给出各挑战的解决日期，故**不把"9→10"当作窗口内增量**。**#19 RawVec** 的 VeriFast 解（PR #422）已于 **2025-08-14** 合并，不在窗口内；挑战 #15（SIMD intrinsics）以 Testable Models（可执行模型的随机测试）解决早在 2025-10 底稿即有，仅作背景：说明"证明"口径在挑战赛内部也包含模型测试路线。原报告指出的并发缺口**仍未补齐**：#7 原子类型与 #27 Arc 依旧 Open[^18^]。

其余工具的变动较小：Prusti 的正式 release 仍停留在 2024-03，但 nightly 构建持续（2026-10-23 仍有 nightly release）[^19^]；Verus、Creusot 保持滚动发布节奏（第三方资料分别提及 2026.08.30 滚动版与 v0.13.0，此处按中置信记录，不作核心结论）。

## 5. 内核与产业：Rust 在内核与大厂工程体系中的地位继续上升

内核侧的节奏没有放缓。Linux 7.3 合并窗口中，DRM 的 Rust core 基础设施继续完善，两个旗舰 Rust DRM 驱动同步推进：**Nova** 增加 vGPU 启动支持、TLV 固件格式支持并改进 Hopper/Blackwell 代码，**Tyr**（Arm Mali）持续上游化（Tyr 此前已合入 6.18，背景见[^21^]）[^20^]。Kangrejos/LPC 2026 的 LWN 系列议题显示，讨论重心正从"能否用 Rust"转向**更深层的抽象与互操作**：用 Charon 分析 Rust 程序（10-07）、从 Rust 拥有 C 类型（10-13）、内核 Rust 的安全自引用数据结构（10-16）、跨 crate 前向声明（10-19）、XArray 重写讨论（10-20）以及 Rust 未来特性（10-22）[^22^]。

**gccrs 需要修正原报告转述的乐观预期**（以下主要依据单一 LWN 报道，中置信）。RustConf 2026 与 Kangrejos 的演讲（LWN 2026-09-22 报道）明确：gccrs **目前仍不能编译 Linux 内核**，团队把阶段目标戏称为"先 miscompile 内核"——先无报错接受代码并产出可测试二进制，再验证行为等价。积极进展是名称解析与声明宏展开已完成（历时约三年），core 编译时间经缓存从 42 分钟降至 3 分钟（rustc 约 30 秒）；过程宏需要 std 的问题正在讨论"先用 rustc 编译 proc-macro"的过渡方案。此外据 LWN 报道，两名核心开发者（Cohen 与 Patry）曾被解雇、无法全职投入，其合同已由 Open Source Security 接手（LWN 未提及雇主名称）[^23^]。

产业侧的标志性事件是**微软自述将 Rust 列为内部 Tier-1 语言**（2026-09-10，Rust Foundation 客座文章，厂商自述、单一来源，中低置信）：与 C++、C#、TypeScript 同级，意味着安全工具链、开发者工具、质量流程、平台集成与 SDL 合规的完整"铺路"。技术核心是 **rustc_codegen_utc**——把 rustc 接到 MSVC 后端，使 Rust/C++ 共享 Windows 平台的加固、热补丁、跨语言内联与调试体系；该后端 2026 年初生产可用、自 Rust 1.90 起自托管，已有 100+ 微软仓库使用[^24^]。加上此前 Linux 内核"实验结束"与 Android 出货，Rust 在这些大型工程体系中正从"可选项"走向常规选项；但微软一例仅有厂商自述，Linux 内核也不是平台厂商，不宜据此并称"两大平台厂商默认"。

## 6. 政策与供应链安全：CRA 义务生效，攻击面转向"人与工具链"

欧盟 CRA（Regulation (EU) 2024/2847）的**主动利用漏洞报告义务已于 2026-09-11 起适用**（原报告预告的时间点已到），主要义务仍在 2027-12-11；这会持续把漏洞披露、SBOM 与依赖审计变成合规动作[^25^]。2026-10-27 核查 CISA 内存安全语言指南页（发布于 2025-06-24，其相关资源栏无更新的内存安全指南）、CISA 新闻列表首页（2026-09-08 至 10-26 的 10 条均与内存安全无关）及网络检索，未发现窗口内新的内存安全专项指南；NSA 新闻稿页返回 403 未能核查，CISA 新闻列表未覆盖 8 月，故非穷尽核查。DARPA TRACTOR 方面，公开测试语料与评估脚本的仓库底稿记为 2026-02（早于窗口，仅作背景）；"首份评估报告经官方 GitHub 发布"此前仅见于二手论文引用；2026-10-28 复核 DARPA-TRACTOR-Program/Reports 仓库，其中已有 First_TRACTOR_Evaluation_Report.pdf（该仓库提交记录显示 2026-02-20 上传，2026-10-26 提交"Updated first evaluation report"）与 Second_TRACTOR_Evaluation_Report.pdf（2026-10-26 提交"Release second evaluation report"，属窗口内新增）；MIT LL 页面亦链接 Round 1 报告；两份 PDF 的正文与结论未能读取，故其内容不作结论，仅确认报告存在与发布日期（上一版"未见评估报告"的核查对象是 PUBLIC-Test-Corpus 仓库，查错了位置）；参评方包括 aarno、galois、harvest、intel、uwisc、yale 等团队（低置信）[^26^][^27^]。Ferrocene 26.08.0（2026-10-16 发布，公告页称"today"）纳入 Rust 1.96/1.97，并新增三个安全认证目标：`armv7r-none-eabihf`（Armv7-R 硬浮点裸机）、`aarch64-unknown-qnx` 与 `x86_64-pc-qnx`（QNX SDP 8.0+）；其认证口径保持为编译器 ISO 26262 ASIL D / IEC 61508 SIL 3 / IEC 62304 Class C，core 子集 SIL 2 / ASIL B，SIL 4 与 DO-178C DAL C 为支持客户认证方向[^28^]。

窗口内三起官方安全事件值得单独列为**供应链与工具链风险**：

1. **arrayref 投毒（2026-08-20）**：`proc-macro1` 等 6 个恶意 crate 通过 build script 下载恶意载荷；热门 crate `arrayref` 被重新发布并依赖恶意包，`arrayref@0.3.10` 在线 86 分钟即被删除，`internment@0.8.7`、`append-only-vec@0.1.9` 分别在线 90、107 分钟。官方判断作者本人无恶意，其设备或凭据疑似被控制，Nextron Systems 首先报告[^29^]。
2. **针对维护者的定向社会工程（2026-09-17）**：crates.io 团队与安全响应组警告，攻击者以求职/合作视频面试为诱饵，诱导 rust-lang 成员与热门 crate 所有者安装"缺失的音频编解码器"或执行剪贴板中的命令，目的是接管设备与账号以发布恶意包；官方指出 arrayref 事件走了相似路径，攻击手法符合 DPRK 已知 tradecraft 但未作归因[^30^]。
3. **Miri 环境变量经 CI 缓存泄漏（2026-09-21）**：Miri 为多次调用保留构建相关环境变量，实现上把**全部环境变量写入 `target/`**；若 GitHub Actions 缓存 `target/` 且 job 暴露 secrets，PR 可经缓存读取。2026-09-22 nightly 起 Miri 只保留 `CARGO_*`（不含 token）与 `OUT_DIR`；官方生态扫描发现 1 个仓库存在该问题、7 个需警惕，OpenAI 报告并赞助扫描[^31^]。

这三件事共同说明：**"Rust 安全"不等于"Rust 工程链路安全"**。依赖冷却期（推迟数天升级）、`cargo audit`（仅能事后拦截已公告漏洞，对恶意包公告前的窗口无效）、CI 缓存与 secrets 隔离、维护者 MFA 与面试流程核验，应进入与 unsafe 审计同级的检查清单。

## 7. 漏洞与审计生态：tokio 双公告与 panic-safety 聚类

### 7.1 tokio：两条公告，两类失败

**RUSTSEC-2026-0384**（2026-10-22 发布）：Tokio v1.54.0 在多线程运行时中，`Interval::poll_tick` 与时间驱动存在竞态，可在 safe Rust 中造成 waker 与任务状态的数据竞争和 use-after-free，表现为断言 panic、任务引用计数损坏或堆破坏；因已导致生产崩溃，**1.54.0 被 yank**，修复版本 ≥1.54.1（CVE-2026-115567，仅影响 1.54.0，`Sleep`/`Timeout` 不受影响）[^32^]。**RUSTSEC-2026-0386**（2026-10-23 发布，影响 1.51/1.53/1.54 多条版本线，与 0384 的单版本问题不同）：`AsyncFd::new` 等**安全构造器**接受任意 `T: AsRawFd`，无法保证 fd 所有权与有效性；fd 被复制、关闭并被 OS 复用后，析构会错误注销并释放他者资源，形成 use-after-free。修复方式不是"把检查做得更好"，而是**自 1.51.6/1.53.3/1.54.0 起弃用这些安全构造器，改用 `unsafe` 的 `register`/`register_with_interest`**，把"fd 在 AsyncFd 存活期间保持有效、打开且不被替换"的义务交还调用方[^33^]。其中 0386 是原报告"unsafe trait/unsafe fn 是 API 设计抉择"的反向教材：**当不变量无法由类型与文档低成本保证时，把 API 标为 unsafe 比维持虚假的安全抽象更诚实**；0384 则是纯并发实现缺陷（未涉及 API 转 unsafe），只印证"并发不变量优先"。

### 7.2 panic-safety 成为最突出聚类

窗口内 RustSec 出现了一大批**元素或谓词的 `Drop` panic 导致 double free / use-after-free** 的公告：`owned-alloc`（0291）、`imbl-sized-chunks`（0292）、`ringbuf`（0293）、`rtrb`（0274）、`unicycle`（0298）、`skiplist`（0300）、`stack_collections`（0301）、`aligned_box`（0282）、`stable-vec`（0267）、`sp-sized-chunks`（0254）、`circular-buffer`（0256）、`stack_dst`（0272）等[^34^]。此外还有 `lru`（0253，`LruCache::pop` 缺 panic safety）、`orx-split-vec`（0252，未初始化读）等同类问题[^35^]。这与原报告 8.2 节"panic safety 最小义务"完全同构：**在元素可能被析构的容器操作里，先恢复不变量再允许 panic 传播**（RAII guard/Hole 模式）不是风格建议，而是这批事故反复验证的硬约束。对审计者而言，这类公告的高频出现意味着应把"Drop panic 路径"列为含 unsafe 依赖的固定审查项。

### 7.3 其他值得关注的公告

- **zstd-safe / zstd-sys（2026-10-26 集群）**：多条 unsound 与漏洞——`DCtx::try_clone` double free（0404）、多场景 use-after-free（0395/0400/0406）、`OutBuffer::around_pos` 暴露未初始化内存（0397）、`InBuffer::pos` 越界读（0405）、`Seekable::decompress` 把 `Vec` 长度设置超过容量（0398），以及 zstd-sys 的 WebAssembly allocator shim 在分配失败时破坏内存（0410）。FFI 封装层的不变量（pos 范围、frame 生命周期、set_len 纪律）再次成为主角[^36^]。
- **密码学实现**：`pqc_kyber`（0290）与 `cosmian_kyber`（0288）的 AVX2 后端跳过 Fujisaki-Okamoto 隐式拒绝，可被选择密文攻击恢复密钥（HIGH）；`libcrux-hmac-drbg`（0329）与 `libcrux-kem`（0330/0331）存在特定输入下 panic；`bip322`（0334）为 CRITICAL 的地址所有权验证绕过[^37^]。
- **基础设施 crate**：`rustls`（0285，TLS 1.3 握手消息跨加密层被错误接受）、`wasmtime`（0268/0269，WASIp3 流致宿主堆分配与文件系统沙箱逃逸）、`wasapi`（0332）、`salsa`（0308）、`lockfree`（0284）、`faster-hex`（0306，AVX2 路径越界读）、`stack-graphs`（0302，C API 以 safe extern "C" 导出）、`rkyv`（0233）等[^38^]。`rkyv`（0233，反序列化 UAF，2026-05-11 报告，**2026-08-04 发布**）位于窗口内；`pqc_kyber`/`cosmian_kyber`（0290/0288）均发布于 2026-09-18。以上及本节其余 ID 的发布日期均已对照 RustSec 公告索引逐条核对，全部落在 2026-08-02 至 10-27 之内；唯一的窗口前条目是 RUSTSEC-2026-0224（2026-08-01，见下条背景）。
- **与此前解读的衔接**：`nostr-relay-pool` 于 2026-08-09 被标记 **unmaintained**（RUSTSEC-2026-0243），其功能已并入 `nostr-sdk` ≥0.45.0，公告建议迁移；因此 RUSTSEC-2026-0224 的修复版本 0.44.2 更多是过渡方案，**迁移到 nostr-sdk 才是长期路径**[^39^]。

整体看，原报告"unsound 公告加速"的观察在窗口内延续，且**头部 crate（tokio、rustls、zstd、libcrux）也无法免疫**；`cargo audit` 与升级纪律对已公告漏洞收益直接，但属事后拦截。

## 8. 原报告"遗留未决"逐项状态（截至 2026-10-27）

| 遗留项 | 状态 | 依据 |
|---|---|---|
| Tree Borrows 何时成为 Miri 默认 | **无变化**：SB 仍默认，TB 可选且更实验性，无 FCP | Miri README、UCG #573（2026-10 核查）[^8^][^9^] |
| UCG #584 `writable` 之争 | **状态未知**：本次未核查到 #584 本身的决议或最新讨论（Miri README 提及隐式写调节旗标，不构成 #584 的证据） | UCG #584 未核查 |
| rust#132898 miscompile | **未修复但有推进**：保守 PR 关闭，精确 gate 方案附验证记录，待评审 | rust#132898[^10^] |
| `missing_safety_doc` 等 lint 升 hard error 时间表 | **本次未核查**（1.98 新增的 FFI/运行时符号 lint 与该命题无关，不作依据） | — |
| SAFETY 注释标准化 | **仍 Pre-RFC/审阅中**：Rust Safety Standard 讨论中；Safety Tags RFC 以 2026-04 论文 v2 为据，当前状态本次未核查（中低置信） | internals、arXiv v2[^13^][^14^] |
| FLS 首个 rust-lang 自有版本 | **未见发布**；README 仍声明非 normative | rust-lang/fls[^11^] |
| std 挑战泛型与并发缺口 | **并发无变化（#7/#27 仍 Open）；泛型为工具能力扩展**（Kani 0.68 Autoharness 支持泛型），缺口（被跳过的 9,635 个函数）未量化复测，挑战侧是否缩小未核实 | Kani releases、verify-rust-std[^17^][^18^] |
| （补充）gccrs 2026-09 内核构建预期 | **未达成**：官方仍称不能编译内核，core 编译已大幅提速 | LWN 2026-09-22[^23^] |

## 9. 对实践者的更新建议

1. **版本纪律**：使用 1.98.0 的项目必须升级到 ≥1.98.1（vtable miscompile）；使用 tokio 1.54.0 的必须升级 ≥1.54.1（该版本已 yank）；评估 1.99 的 `Box::leak` 新文档对既有 unleak 代码的影响[^3^][^32^][^4^]。
2. **API 迁移**：排查 `AsyncFd::new/with_interest/try_new/try_with_interest` 调用，按 1.51.6/1.53.3/1.54.0 的弃用指引迁移到 `unsafe register`，并把 fd 生命周期不变量写进 SAFETY 注释[^33^]。
3. **CI 安全**：若 CI 运行 `cargo miri` 且缓存 `target/`，立即按官方指引禁用该 job 缓存或隔离 secrets 并清空旧缓存；通用原则是**能写公共缓存的 job 不应接触 secrets**[^31^]。
4. **供应链**：为依赖升级设置冷却期，持续运行 `cargo audit`（可事后发现本窗口 tokio/rustls/zstd 等已公告漏洞；但它对 arrayref 这类恶意包无效——后者 86 分钟即被下线，公告前后均不会触发，需靠冷却期与锁文件审查）；维护者按官方建议核验 MFA、登录历史与面试邀约真实性[^29^][^30^]。
5. **验证工具升级**：含泛型 unsafe 代码的项目可试用 Kani 0.68 的 Autoharness（泛型函数、裸指针/切片参数、构造器驱动与不变量挖掘），但仍需用 Miri 覆盖别名 UB，并关注挑战赛 #7/#27 的并发空白[^17^][^18^]。
6. **长期跟踪**：T-opsem 以 iceoryx2 为试点的 normative 文档、Safety Tags RFC、#132898 修复方案、FLS 首版与 TB 定案，是下一季度最值得盯的五个节点[^12^][^14^][^10^][^11^][^9^]。

## 10. 结论

这三个月印证了原报告的主线判断，但重心有所移动：**"语义定案"依旧缓慢**，TB/FLS/SAFETY 标准化都没有跨过临界点；**"工程化与合规化"显著提速**，从 Kani 的泛型支持、挑战赛扩容，到微软 Tier-1、CRA 义务生效，unsafe 边界的工具与制度投入都在增加。与此同时，tokio 双公告和 panic-safety 聚类说明**抽象设计与析构路径仍是 Rust 事故的主产区**，而 arrayref、定向攻击与 Miri 泄漏则提醒：下一阶段的"Rust 安全"叙事必须把**供应链、维护者与 CI 工具链**纳入同一个威胁模型。对团队而言，最有效的动作仍然朴素：及时升级、审计依赖、把不变量写清楚、让工具（Miri/Kani/loom/cargo audit）在 CI 中长期运行。

# 参考文献

[^1^]: Announcing Rust 1.98.0 — Rust 官方博客，2026-08-20. https://blog.rust-lang.org/2026/08/20/Rust-1.98.0/
[^2^]: Rust Release Notes, Version 1.98.0 (2026-08-20)（Language 栏：runtime symbol 与 c_void_returns lint；这三条 lint 未出现在博客公告中，故引固定版本的 release notes） — Rust 官方文档. https://doc.rust-lang.org/1.98.0/releases.html
[^3^]: Announcing Rust 1.98.1（修复 vtable 生成 miscompilation） — Rust 官方博客，2026-09-03. https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/
[^4^]: Announcing Rust 1.99.0（extern "C" variadics、裸指针布局查询、Vec/Box 互转、Box::leak 文档） — Rust 官方博客，2026-10-01. https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/
[^5^]: Rust 官方博客与 releases 索引（1.99.1，2026-10-15；发布节奏） — Rust 官方，2026-10 抓取. https://blog.rust-lang.org/releases/
[^6^]: Enabling the next iteration of the borrow checker on nightly（2026-08-04）；Enabling the next-generation trait solver on nightly（2026-08-21） — Rust 官方博客. https://blog.rust-lang.org/2026/08/04/enabling-polonius-alpha-on-nightly/；https://blog.rust-lang.org/2026/08/21/enabling-next-solver-on-nightly/
[^7^]: RFC 3935 Project Goals 2026（Polonius Alpha、下一代 trait solver、Project Zero） — rust-lang/rfcs. https://github.com/rust-lang/rfcs/blob/master/text/3935-Project-Goals-2026.md
[^8^]: Miri README（SB 默认、TB 可选与实验性警告） — rust-lang/miri，2026-10 抓取. https://github.com/rust-lang/miri/blob/master/README.md
[^9^]: UCG #573 Strengthening Tree Borrows so that we can discard Stacked Borrows — rust-lang/unsafe-code-guidelines，2026-10 抓取仍 open. https://github.com/rust-lang/unsafe-code-guidelines/issues/573
[^10^]: rust-lang/rust #132898 ReferencePropagation introduces UB into code that is accepted by Stacked Borrows — 2026-10 抓取（含 #156896 与精确 gate 方案讨论）. https://github.com/rust-lang/rust/issues/132898
[^11^]: rust-lang/fls README（FLS 定位与非 normative 声明） — 2026-10 抓取. https://github.com/rust-lang/fls
[^12^]: Normative Documentation for Sound unsafe Rust（2026 项目目标 #644，iceoryx2 试点） — rust-lang goals. https://goals.rust-lang.org/2026/safe-unsafe-for-safety-critical.html
[^13^]: Pre-RFC: Rust Safety Standard — Rust Internals，2026-01-31 起. https://internals.rust-lang.org/t/pre-rfc-rust-safety-standard/23963
[^14^]: Annotating and Auditing the Safety Properties of Unsafe Rust（safety-tags，v2） — arXiv:2504.21312v2，2026-04-22（时点为 2026-04，不能证明 10 月状态）. https://arxiv.org/html/2504.21312v2
[^15^]: Tracking Issue for stabilizing the sanitizers（rust#123615，总跟踪 issue）与 sanitizers: Stabilize AddressSanitizer and LeakSanitizer（rust#123617，ASan/LSan 稳定化实现 PR，含 Tier 2 默认 ASan target） — rust-lang/rust. https://github.com/rust-lang/rust/issues/123615；https://github.com/rust-lang/rust/pull/123617
[^16^]: Stabilize MemorySanitizer and ThreadSanitizer Support（2026 项目目标） — rust-lang goals. https://goals.rust-lang.org/2026/stabilization-of-sanitizer-support.html
[^17^]: Kani 0.68.0 release notes — model-checking/kani，0.68.0 发布于 9 月 16 日（页面未显示年份，2026-10 抓取）. https://github.com/model-checking/kani/releases
[^18^]: verify-rust-std 挑战赛总表（认可工具含 KMIR；10/29 Resolved；#19 RawVec Resolved by VeriFast；#7/#27 Open） — model-checking/verify-rust-std，2026-10 抓取. https://github.com/model-checking/verify-rust-std；KMIR 认可：Tool Application 议题 #296 与 PR #310（2026-08-21）https://github.com/model-checking/verify-rust-std/pull/310；#19 解：PR #422（2025-08-14 合并）https://github.com/model-checking/verify-rust-std/pull/422
[^19^]: Prusti releases（正式版停留 2024-03，nightly 持续至 2026-10-23） — viperproject/prusti-dev. https://github.com/viperproject/prusti-dev/releases
[^20^]: Open-Source NVIDIA "Nova" Driver Sees More Functionality For Linux 7.3 — Phoronix，2026-08-10（Linux 7.3 合并窗口 DRM Rust 变化）. https://www.phoronix.com/news/NVIDIA-Nova-Rust-Linux-7.3
[^21^]: Introducing Tyr, a new Rust DRM driver — Collabora，2025-07-07（仅支撑 Tyr 的背景，不支撑 RustConf 2026 相关断言）. https://www.collabora.com/news-and-blog/news-and-events/introducing-tyr-a-new-rust-drm-driver.html
[^22^]: LWN Kangrejos 2026 系列（Charon 10-07、Owning C types 10-13、安全自引用 10-16、跨 crate 前向声明 10-19、XArray 10-20、Rust 未来特性 10-22） — LWN.net. https://lwn.net/Articles/1097198/；https://lwn.net/Articles/1099015/；https://lwn.net/Articles/1099224/；https://lwn.net/Articles/1099596/；https://lwn.net/Articles/1100520/；https://lwn.net/Articles/1099606/
[^23^]: Compiling the kernel with gccrs（RustConf 2026 与 Kangrejos 演讲报道） — LWN.net，2026-09-22. https://lwn.net/Articles/1095553/
[^24^]: Guest Post: Rust Is Tier-1 Language at Microsoft — Rust Foundation，2026-09-10. https://rustfoundation.org/media/guest-post-rust-is-tier-1-language-at-microsoft/
[^25^]: Regulation (EU) 2024/2847（CRA；Art.14 报告义务 2026-09-11 起适用） — EUR-Lex. https://eur-lex.europa.eu/eli/reg/2024/2847/oj
[^26^]: Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development — CISA/NSA，2025-06-24（2026-10-27 核查本页相关资源栏、CISA 新闻列表首页与网络检索，未见更新；NSA 新闻稿页 403，非穷尽核查）. https://www.cisa.gov/resources-tools/resources/memory-safe-languages-reducing-vulnerabilities-modern-software-development
[^27^]: DARPA-TRACTOR-Program/PUBLIC-Test-Corpus（公开测试语料与评估脚本） — GitHub，仓库底稿记为 2026-02（窗口前背景）；该仓库 README/Releases 无评估报告；评估报告见 DARPA-TRACTOR-Program/Reports（First_TRACTOR_Evaluation_Report.pdf，2026-02-20 上传、2026-10-26 更新；Second_TRACTOR_Evaluation_Report.pdf，2026-10-26 发布，PDF 正文未读取）. https://github.com/DARPA-TRACTOR-Program/PUBLIC-Test-Corpus/ ; https://github.com/DARPA-TRACTOR-Program/Reports
[^28^]: Ferrocene 26.08.0 发布公告 — Ferrocene/Ferrous Systems，2026-10-16. https://ferrocene.dev/blogs/ferrocene-26080/
[^29^]: Supply chain attack on arrayref — Rust 官方博客，2026-08-20. https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
[^30^]: Be alert: targeted attacks on prominent Rustaceans — Rust 官方博客，2026-09-17. https://blog.rust-lang.org/2026/09/17/targeted-attacks/
[^31^]: GitHub Actions leaking secrets when Miri output is cached — Rust 官方博客，2026-09-21. https://blog.rust-lang.org/2026/09/21/github-actions-leaking-secrets-when-miri-output-is-cached/
[^32^]: RUSTSEC-2026-0384: Race condition in tokio::time::Interval on Tokio v1.54.0 — RustSec，2026-10-22. https://rustsec.org/advisories/RUSTSEC-2026-0384.html
[^33^]: RUSTSEC-2026-0386: AsyncFd::new and related constructors violate I/O safety — RustSec，2026-10-23. https://rustsec.org/advisories/RUSTSEC-2026-0386.html
[^34^]: RustSec 公告（panic-safety 系列，12 条） — RustSec. （panic-safety 系列，各条独立页面；发布日期据 RustSec 索引：0254/0256 为 08-12，0267 为 08-24，0272 为 08-31，0274 为 09-01，0282 为 09-09，0291/0292/0293 为 09-21，0298/0300/0301 为 09-22，均在窗口内） https://rustsec.org/advisories/RUSTSEC-2026-0291.html；https://rustsec.org/advisories/RUSTSEC-2026-0292.html；https://rustsec.org/advisories/RUSTSEC-2026-0293.html；https://rustsec.org/advisories/RUSTSEC-2026-0274.html；https://rustsec.org/advisories/RUSTSEC-2026-0298.html；https://rustsec.org/advisories/RUSTSEC-2026-0300.html；https://rustsec.org/advisories/RUSTSEC-2026-0301.html；https://rustsec.org/advisories/RUSTSEC-2026-0282.html；https://rustsec.org/advisories/RUSTSEC-2026-0267.html；https://rustsec.org/advisories/RUSTSEC-2026-0254.html；https://rustsec.org/advisories/RUSTSEC-2026-0256.html；https://rustsec.org/advisories/RUSTSEC-2026-0272.html
[^35^]: RUSTSEC-2026-0253（lru，panic safety）与 RUSTSEC-2026-0252（orx-split-vec，未初始化读） — RustSec，2026-08-11. https://rustsec.org/advisories/RUSTSEC-2026-0253.html
[^36^]: zstd-safe / zstd-sys 公告集群（8 条） — RustSec. （据 RustSec 索引，0395/0397/0398/0400/0404/0405/0406/0410 均发布于 2026-10-26） https://rustsec.org/advisories/RUSTSEC-2026-0395.html；https://rustsec.org/advisories/RUSTSEC-2026-0397.html；https://rustsec.org/advisories/RUSTSEC-2026-0398.html；https://rustsec.org/advisories/RUSTSEC-2026-0400.html；https://rustsec.org/advisories/RUSTSEC-2026-0404.html；https://rustsec.org/advisories/RUSTSEC-2026-0405.html；https://rustsec.org/advisories/RUSTSEC-2026-0406.html；https://rustsec.org/advisories/RUSTSEC-2026-0410.html
[^37^]: pqc_kyber/cosmian_kyber（0290/0288）、libcrux（0329/0330/0331）、bip322（0334）公告 — RustSec. （据 RustSec 索引：0288/0290 为 2026-09-18，0329/0330/0331 为 10-07，0334 为 10-09） https://rustsec.org/advisories/RUSTSEC-2026-0290.html；https://rustsec.org/advisories/RUSTSEC-2026-0288.html；https://rustsec.org/advisories/RUSTSEC-2026-0329.html；https://rustsec.org/advisories/RUSTSEC-2026-0330.html；https://rustsec.org/advisories/RUSTSEC-2026-0331.html；https://rustsec.org/advisories/RUSTSEC-2026-0334.html
[^38^]: rkyv（0233）、rustls（0285）、wasmtime（0268/0269）、wasapi（0332）、salsa（0308）、lockfree（0284）、faster-hex（0306）、stack-graphs（0302）公告 — RustSec. （据 RustSec 索引：0268/0269 为 08-31，0284/0285 为 09-14，0302 为 09-22，0306 为 09-23，0308 为 09-24，0332 为 10-07；rkyv 0233 为 08-04 发布，在窗口内） https://rustsec.org/advisories/RUSTSEC-2026-0285.html；https://rustsec.org/advisories/RUSTSEC-2026-0268.html；https://rustsec.org/advisories/RUSTSEC-2026-0269.html；https://rustsec.org/advisories/RUSTSEC-2026-0332.html；https://rustsec.org/advisories/RUSTSEC-2026-0308.html；https://rustsec.org/advisories/RUSTSEC-2026-0284.html；https://rustsec.org/advisories/RUSTSEC-2026-0306.html；https://rustsec.org/advisories/RUSTSEC-2026-0302.html；https://rustsec.org/advisories/RUSTSEC-2026-0233.html
[^39^]: RUSTSEC-2026-0243: nostr-relay-pool is unmaintained（功能并入 nostr-sdk ≥0.45.0） — RustSec，2026-08-09. https://rustsec.org/advisories/RUSTSEC-2026-0243.html
