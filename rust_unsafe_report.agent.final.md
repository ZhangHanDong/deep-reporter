# Rust 安全抽象与 unsafe Rust 生态全景调研：机制、工具链、最新进展与最佳实践

## 摘要

本报告以 2026-08 为时效锚点，基于 6 份宽探索、12 份维度深潜与一轮交叉验证，对 Rust 安全抽象与 unsafe Rust 的语义基础、别名模型、验证工具链、内核实践、政策环境与最佳实践进行全景调研；关键数据优先锚定官方文档、政府文件、顶会论文与官方公告等一手来源，部分背景引用二手来源（已在正文与参考文献中标注），并对冲突口径逐项裁定。核心结论如下：

- **现有有限证据与"风险重心位于 unsafe 边界"一致，但样本很小。** Linux 内核 Rust 驱动的 unsafe 代码占比为 0.76%–3.4%（驱动自身口径）[^1^]；Android 侧 Rust 漏洞密度估计为 0.2 个/百万行（仅基于单一 near-miss 的保守估计），较平台 C/C++ 历史值约 1000 个/百万行低约三个数量级[^2^]。截至 2026-08 锚点，首个公开分配 CVE 的内核 Rust 代码缺陷（CVE-2025-68260）恰恰发生在 SAFETY 注释遗漏的状态分支上[^3^]。一个内核 CVE 加一个 Android near-miss 不足以作统计性结论，只能说与"剩余风险集中于 unsafe 边界上的不变量论证"这一判断相符。
- **工具链进入"验证入 CI"时代，但存在别名与并发盲区。** AWS 主导的 verify-rust-std 挑战已将标准库验证纳入持续集成，但 Kani 明确不建模 Stacked Borrows/Tree Borrows 别名规则、不支持并发，Miri 属动态检测，其论文微基准（计算密集负载）下的性能开销达 3,000–7,000 倍[^4^][^5^]。"已验证"声明的保证范围必须逐项核查。
- **语义规范化双轨并进，Tree Borrows 定案是中期最大变量。** MiniRust 成为事实语义候选、Ferrocene Language Specification（FLS）于 2025-03 捐赠 Rust 项目[^6^]；别名模型在 Stacked Borrows 与 Tree Borrows 之间尚无 canonical 定案，T-opsem 团队 2026 年目标为发布"sound unsafe Rust"规范性文档。
- **政策压力在上升，但尚无文件直接要求 unsafe 审计。** 美国 NSA/CISA 系列文件均为 non-binding 指南，欧盟《网络弹性法案》（CRA）技术中立、不指定语言，其报告义务于 2026-09-11 起适用（以 2026-08 锚点计尚未到期）[^7^][^8^]；与此同时，在 160 名问卷调查受访者中 88% 审计依赖 unsafe 的频率不足一半，审计供给明显不足[^9^]。unsafe 审计是否会成为供应链准入项，属本报告的推断而非政策文本。

报告第 2–3 章建立语义与别名模型的理论基础，第 4–5 章评估验证与检测工具生态，第 6 章复盘内核实践，第 7 章梳理政策与产业采纳，第 8 章提炼最佳实践，第 9 章展望学术前沿与趋势，第 10 章给出结论。

## 1. 引言：调研范围、方法与时效锚点

### 1.1 调研背景与问题定义

#### 1.1.1 内存安全漏洞的产业背景与 Rust 的应答定位

内存安全长期是严重漏洞的首要成因。微软安全响应中心（MSRC）2019 年披露，其每年分配 CVE 的漏洞中约 70% 为内存安全问题（统计口径 2006–2018 年）[^10^]；CISA 联合五眼 8 机构 2023-12 发布的指南援引"约三分之二软件漏洞源于内存不安全编码"的研究结论[^11^]。NSA/CISA 2025-06 联合指南进一步给出动态数据：微软 CVE 内存安全占比已从近 70% 降至约 50%（2016–2023 年口径，该数字出自官方指南而非微软自报；NSA PDF 在 2026-10-28 复核时返回 403，此数字未能直读核实，沿用此前底稿）[^7^]。产业侧的实证更为直接：Android 内存安全漏洞占全部漏洞比例从 2019 年的 76% 降至 2024 年的 24%，2025 年首次跌破 20%，其策略是"新代码用 Rust/Java、旧代码不重写"[^12^][^2^]。Rust 以所有权与借用检查在编译期排除数据竞争与悬垂访问，同时保留零成本抽象与无垃圾回收（GC）的系统级性能，由此成为各份政策文件共同点名的内存安全语言应答方案。

#### 1.1.2 问题定义：unsafe 是证明义务而非安全体系漏洞

本报告的核心命题是：`unsafe` 关键字不构成 Rust 安全体系的漏洞，而是一套显式的证明义务（proof obligation）机制。《Rust Reference》17.1 章已采纳 RFC 2585 框架，将 `unsafe` 统一表述为"定义（define）或消解（discharge）安全证明义务"——unsafe 块内的程序员断言承担了编译器无法自动核查的安全条件[^13^]。这一定位获得有限的实证支撑：在所测样本中 unsafe 代码占比较小（内核驱动 0.76%–3.4%，kernel 抽象层 crate 约 9.2%–9.7%）[^1^]；另需澄清，Miri 对 59,136 个有测试的 crate 的实证中 7.8%（4,595 个）触发 undefined behavior（UB，未定义行为）[^5^]，但分母是所有有测试的库、7.8% 是 UB 检出率，不是 unsafe 占比，不能据此推断 unsafe 占比小；而 CVE-2025-68260 的根因并非 unsafe 机制失效，而是 SAFETY 注释的二分论证遗漏了"元素在栈上临时链表"这一第三状态，属于不变量论证不完整[^3^]。因此，评估 Rust 项目安全性的首要问题不是"用了多少 unsafe"，而是"unsafe 边界上的不变量是否被文档化、被测试、被验证"——本报告即围绕这一边界展开。

### 1.2 调研方法

#### 1.2.1 多代理调研流程与来源分级

调研采用"宽探索—维度深潜—交叉验证"三段式多代理方法：第一阶段 6 份宽探索（wide01–06）覆盖语义、别名模型、工具、审计、内核、政策六大侧面；第二阶段 12 个维度深潜（dim01–12）代理先读宽报告，再对关键数据点执行一手来源核实；第三阶段交叉验证汇总置信分级并对 13 处冲突口径逐项裁定。来源执行三级优先级：T1（官方文档、政府/标准组织文件、顶会论文、官方公告）优先于 T2（主流媒体、官方公司博客），内容农场与匿名论坛来源不予采用；全部关键量化主张标注统计口径与年份。

#### 1.2.2 时效锚点、置信分级与冲突裁定规则

本报告时效锚点为 **2026-08**，优先采用 2024–2026 年数据，更早数据（如微软 70% 的 2006–2018 口径）均在引用处注明年份。置信度分高/中/低三级：高置信要求 ≥2 个独立来源或一手来源直读确认；单一权威来源为中置信，正文保留来源归属；低置信素材（如 DARPA TRACTOR 的"95% 自动化、unsafe<5%"指标仅见单一第三方报道）加"据单一来源报道、待核实"限定语。冲突口径按交叉验证裁定呈现并注明依据，典型案例包括：Miri 性能开销以 POPL 论文 3,000–7,000 倍为准、二手博文的 10–50 倍口径标注差异[^5^]；"verify-rust-std 17 个工具白名单"经仓库直读证伪，官方 Approved 工具远少于 17 个（2026-10-27 复核：仓库 README 列 Flux、ESBMC、Kani、KMIR、VeriFast 5 个，tools.md 另含 RAPx 共 6 个；2026-08 抓取口径为 4 个，清单随时间变动，详见 9.2.1）[^4^]；"unsafe 行比 C 行更易错"的流行说法被 Google 实测否定[^2^]。调研遗留的未决问题（Tree Borrows 成为 Miri 默认无正式 FCP、rust-lang/rust #132898 miscompile 仍 open 等）在各章如实标注。

下表汇总本报告的调研维度划分、覆盖章节与代表性一手来源类型。

| 调研维度 | 覆盖章节 | 代表性一手来源类型 | 数据时效 |
|---|---|---|---|
| 语义基础与 soundness 理论 | 第 2 章 | Reference、Rustonomicon、RFC 文本 | 至 2026-08 |
| 别名模型与操作语义 | 第 3 章 | PLDI'25 论文、UCG issue、Miri README [^14^] | 至 2026-08 |
| 验证工具链与检测工具生态 | 第 4–5 章 | verify-rust-std 仓库、POPL'26/ASE'26 论文、工具官方文档 [^4^][^5^] | 至 2026-08 |
| 内核抽象与系统实践 | 第 6 章 | kernel.org 修复 commit、LPC 官方幻灯、ACSAC'24 论文 [^1^][^3^] | 至 2026-08 |
| 政策环境与产业采纳 | 第 7 章 | NSA/CISA 官方 PDF、EUR-Lex 法规文本、Google 官方博文 [^7^][^8^][^2^] | 政策时间线至 2026-08 |
| 最佳实践与供应链审计 | 第 8 章 | RustSec/MSR'26 论文、官方 lint 与审计工具文档 [^9^] | 2021.01–2025.04 数据快照 |
| 学术前沿与趋势研判 | 第 9 章 | PLDI'26 等顶会论文、rust-lang 项目目标 | 至 2026-08 |

该表反映出两个方法层面的结构性安排。其一，来源类型与各维度证据形态严格对齐：政策维度依赖政府原文 PDF 而非媒体转述（避免了"NSA 名单含 Python""Roadmaps 联署含德国"两类流传讹误），工具维度以仓库直读与论文全文为准（避免了"17 个白名单工具"等二手夸大）。其二，数据时效存在内在梯度：政策与工具链数据刷新至 2026-08，而 RustSec 漏洞库统计截止 2025-04、微软 CVE 口径止于 2023 年，各章引用时须沿用各自的统计窗口而非笼统标注"最新"，这是交叉验证阶段处理口径冲突后形成的统一规则。读者据此可将每章数据放回其对应时间点解读。

## 2. unsafe 的语义基础与 soundness 理论

### 2.1 unsafe 的精确语义

#### 2.1.1 五种超能力与七种 unsafe 上下文：两个不可混用的枚举

`unsafe` 在 Rust 中不是"关闭安全检查"的开关，而是一套精确的契约机制。官方《Rust Book》列举 unsafe 代码相对 safe 代码仅有的五种超能力（superpowers）：解引用裸指针、调用 unsafe 函数或方法、访问或修改可变静态变量（`static mut`）、实现 unsafe trait、访问 `union` 的字段；借用检查器与其余安全检查在 `unsafe` 块内照常运行，教材同时明确"创建裸指针本身无需 unsafe，只有解引用才需要"（此处引自 2024 版教材表述，并不表示该规则是 2024 才引入）[^15^]。这是**操作维度**的枚举。

与之正交的是**语法维度**的枚举。《Rust Reference》17.1 章现已正式采纳 RFC 2585 提出的证明义务（proof obligation）框架，把 `unsafe` 关键字统一表述为"定义（define）或消解（discharge）安全证明义务"：其中 `unsafe fn`、`unsafe trait`、`unsafe static` 属于定义义务的一方，即声明了"别处必须满足的安全条件"；`unsafe {}` 块、`unsafe impl`、`unsafe extern` 块与 `#[unsafe(attr)]` 属性属于消解义务的一方，即程序员断言"此处满足了他处定义的条件"[^13^]。这一框架源自 Ralf Jung 的 RFC 2585（2018 年提出、2020 年接受），其核心洞见是 `unsafe fn` 长期把"unsafe to call"与"函数体即隐式 unsafe 块"两个对偶角色混为一谈，致使有经验的开发者也难以厘清义务归属[^13^]。注意 `unsafe fn` 在未启用相应 lint 时兼具两种角色，而 `unsafe extern` 与 `unsafe static` 是 2024 Edition 新增的上下文——因此"五种超能力"与"七种 unsafe 上下文"分别回答"unsafe 能做什么"与"unsafe 关键字出现在哪里"两个问题，混用会造成概念错位。

#### 2.1.2 UB 清单：下近似枚举与六处"未定"标注

undefined behavior（UB，未定义行为）的边界目前只能以"下近似"方式给出。《Rust Reference》的 "Behavior considered undefined" 页明确警告：清单不完备、可能增删，且"不存在 Rust 语义的形式化模型"，官方甚至保留"未来把清单中某些行为改为已定义"的权利[^16^]。互补的 "Behavior not considered unsafe" 页则划定负边界：死锁、内存泄漏、不运行析构函数、整数二补码回绕溢出等均**不是** UB——`mem::forget` 是 safe 函数正是"泄漏非 UB"的直接推论[^17^]。下表按 Reference 原文将其十条顶层 UB 条目归并为八类，并标注规范化状态。

| UB 类别（顶层条目） | 典型情形 | 规范化状态（截至 2026-08） |
|---|---|---|
| 数据竞争 | 多线程非同步并发访问同一内存 | 已明确，但弱内存语义仍在演进 [^16^] |
| 悬垂或未对齐访问 | 加载/存储基于悬垂或未对齐指针的 place | 已明确（MiniRust 拟放宽"仅解引用裸指针"为已定义）[^16^] |
| 越界 place projection | 违反 in-bounds 指针运算要求 | 已明确 [^16^] |
| 违反指针别名规则 | `&T` 被改写、`&mut T` 不独占 | **未定**：精确规则未决，仅给出原则与存活性上下界 [^16^] |
| 修改不可变字节 | 对超过 0 字节的重叠写（即使内容不变） | 已明确，2023 年后定义扩写 [^16^] |
| intrinsics 滥用 / 错误 target_feature / 错误 ABI 或非法 unwind / 内联汇编误用 | 调用约定、平台特性、汇编约束不满足 | 已明确，逐项列举 [^16^] |
| 产生无效值（invalid value） | 非 0/1 的 `bool`、非法 enum 判别值、未初始化整数 | 即时 UB；有效性按类型逐条定义；const 上下文新增 provenance 限制 [^16^] |
| 违反 Rust 运行时假设 | `longjmp` 跳过 Rust 栈帧析构 | **大多未文档化**，仅少数条目写明 [^16^] |

该表最值得注意的异常值是：作为动态语义核心的**别名规则**恰恰是规范化程度最低的一类。Reference 在该条目下以"原则概述 + 存活性上下界"的方式暂存共识——上界是借用检查器的语法生命周期，下界包括"引用传入函数则至少活到调用结束（`UnsafeCell` 除外）"——这实质上是 T-opsem 把两个候选别名模型的公共部分先行规范化的结果[^16^]。除别名外，清单内明确标注"未定"的还有五处：存活性精确时长、union 的 validity 要求、引用与 `Box`"必须指向有效值"是否成立（原文称"仍有争议"）、裸指针 `dyn Trait` 元数据要求、运行时假设文档化，合计六处[^16^]。另一个结构性事实来自 RFC 3559：Rust 已接受"指针 = 地址 + provenance（来源）"作为长期语义基石，一次访问是否 UB 同时取决于地址与 provenance，而具体 provenance 模型被刻意留白；配套 strict provenance API 于 Rust 1.84（2025-01）稳定，但 std 文档仍声明完整定义未决[^18^]。这意味着今天的 UB 清单既是工程判据，也是一份"未决问题清单"。

### 2.2 soundness 与封装边界

#### 2.2.1 soundness 的全称量化定义与模块私有性边界

soundness（健全性，即 safe 代码无 UB 的保证）的严格定义是**全称量化**的：一段 unsafe 代码是 sound 的，当且仅当**任意** safe 客户端代码都无法通过其公共 API 触发 UB；Reference 已把这一定义从 Unsafe Code Guidelines（UCG）工作文档"毕业"为 UB 页正文的操作化表述[^19^]。《Rustonomicon》将其凝练为 soundness property——"No matter what, Safe Rust can't cause Undefined Behavior"——并指出 safe 与 unsafe 之间是**不对称信任**：safe 代码必须信任 unsafe 写得正确，而 unsafe 代码不能信任 safe 代码，经典案例是 `BTreeMap` 内部的 unsafe 代码必须容忍用户给出的不满足全序的 `Ord` 实现[^20^]。

全称量化之所以在工程上可操作，依赖 Rust 的可见性系统：**模块私有性构成封装边界**。safe 代码无法直接构造私有字段或访问私有函数，因此 unsafe 作者只需论证模块内部不变量在公共 API 的所有调用序列下保持成立——审计范围从"全体可能的调用方"收敛到"本模块的公共接口"。这也是 UB 全局性警示（"undefined behavior affects the entire program"，FFI 另一侧的 UB 同样污染整个程序）在封装层面的对偶结论：soundness 论证以模块为单位，而失败后果以程序为单位[^19^]。

#### 2.2.2 Edition 2024：四项语言收紧、三个 std 函数转 unsafe 与 lint 演进

Rust 2024 Edition（1.85.0，2025-02-20 稳定）是 unsafe 边界的一次系统性收紧，语言侧恰有四项变更[^21^]。其一，`extern` 块强制写为 `unsafe extern`（RFC 3484）：签名正确性的担保责任从调用者部分转移给声明者，块内逐项可用 `safe`/`unsafe` 标注[^22^]。其二，`no_mangle`、`export_name`、`link_section` 三个属性改为 `#[unsafe(...)]` 形式（RFC 3325）：这些属性作用于全局符号命名空间，此前纯 safe 代码中的 `#[export_name = "malloc"]` 即可在多数 Unix 平台致崩，属于"safe 语法可致 UB"的漏洞封堵[^23^]。其三，对 `static mut` 取引用（含 autoref 隐式引用）升为 deny-by-default（`static_mut_refs` lint）——此类引用违反"可变 XOR 别名"约束，历来是即时 UB，即使从不读写该引用；lang 团队曾计划 hard error，2024-08 会议后降格为 lint 以保留 `#[allow]` 逃生口，且官方刻意不提供自动迁移，要求人工逐处审查[^24^]。其四，`unsafe_op_in_unsafe_fn` lint 默认警告：`unsafe fn` 体内的 unsafe 操作须显式置于 `unsafe {}` 块中；该 lint 2021 年前为 allow-by-default，rustc 文档称进一步升级（deny 或 hard error）"仍在考虑中"[^25^]。标准库侧另有一组变更：`std::env::set_var`、`std::env::remove_var` 与 `std::os::unix::process::CommandExt::before_exec` 三个函数新标记为 unsafe[^21^]。

lint 层面的另一条演进线是 `invalid_reference_casting`：未经 `UnsafeCell` 的 `&T`→`&mut T` 强转是即时 UB，该 lint 自 Clippy 上收后于 Rust 1.73（2023-10）起 deny-by-default，2024 年又扩展覆盖"转为比底层分配更大 layout 的引用"；其对 ZST 与 DST 存在已知误报（Miri 在 Stacked Borrows 与 Tree Borrows 下均判定 ZST 强转非 UB），tracking issue 中甚至开放讨论"是否改为默认沉默"[^26^]。这是"lint 严于语义"的公开案例，说明静态检查与动态语义之间仍存在对齐成本。

综合本章，unsafe 的正确心智模型是**证明义务而非漏洞**：`unsafe` 关键字不引入缺陷，而是把编译器无法自动核查的安全条件显式标记为程序员的责任清单。义务由谁定义、由谁消解、在何种语义下成立，正是 RFC 2585 框架、UB 清单与 soundness 定义三者共同回答的问题；而"在何种语义下成立"这最后一环——别名模型与操作语义的规范化——仍处未决状态，构成下一章的主题。

## 3. 别名模型与语义规范化前沿

第 2 章的 UB 清单中，"违反指针别名规则"一条至今标注着"The exact aliasing rules are not determined yet"。本章考察这条未定性规则的两代候选模型——Stacked Borrows（SB）与 Tree Borrows（TB）——的规则差异、定案进程，以及围绕它们的语义规范化工程；截至 2026-08，这是 unsafe Rust 实践最大的中期变量。

### 3.1 Stacked Borrows 到 Tree Borrows

#### 3.1.1 两模型规则对比

Stacked Borrows（POPL 2020）为每个内存位置维护一个"借用栈"，每个指针携带 tag，每次访问检查该 tag 是否仍在栈中且上方无冲突项；引用创建与函数入口处触发 retag 产生新权限项入栈[^14^]。SB 有两个公认的结构性缺陷：其一，对 `&mut` 执行即时唯一性（eager uniqueness），retag 时立即失效所有先前指针，使 `as_ptr()`/`as_mut_ptr()` 交错创建等大量真实惯用法被误判为 UB；其二，子对象限制（subobject confinement）把指针约束在其来源类型的尺寸范围内，使 `container_of`、跨数组元素的指针运算等底层惯用法全部非法[^27^]。

Tree Borrows（TB，Villani 等，PLDI 2025 杰出论文）把栈换成权限树：所有 `&mut` 统一建模为 two-phase borrow，初始为 `Reserved` 态、容忍外来读，首次写入才激活为 `Active` 并要求唯一性；裸指针 retag 是空操作（NOP），直接继承父引用 tag；越出类型范围的访问沿树向上"懒初始化"获取权限[^14^][^28^]。实测层面，论文在 3 万个最常用 crate 上以 crater-at-home 跑测试套件，TB 比 SB 少拒绝 54% 的测试用例；同时经 Rocq 形式化证明，TB 保留了 SB 的绝大多数优化，并额外解锁 SB 无法证明的读-读重排（read-read reordering）——"更少的 UB 反而带来更多优化"[^14^]。

**表 3-1　Stacked Borrows 与 Tree Borrows 核心规则对比**

| 维度 | Stacked Borrows（POPL 2020） | Tree Borrows（PLDI 2025） |
|---|---|---|
| 权限数据结构 | 每位置一个借用栈 + 指针 tag [^14^] | tag 树 + 每节点每字节一台状态机 [^14^] |
| `&mut` 语义 | 即时唯一，retag 即隐式写 [^27^] | 统一 two-phase：Reserved→Active，retag 仅隐式读 [^14^][^27^] |
| 裸指针 retag | 新建 `SharedReadWrite` 栈项，受类型范围与可变性限制 [^27^] | NOP，继承父引用 tag；`*const`/`*mut` 无别名语义差异 [^28^] |
| 越出类型范围访问 | UB（subobject confinement） [^27^] | 合法，沿树懒初始化（兼容 `container_of`、extern type） [^28^] |
| two-phase borrow | 无法建模，退化为裸指针放任别名 [^14^] | 正确建模，激活写后要求真唯一 [^14^] |
| UnsafeCell 追踪精度 | 字节级 [^29^] | 字节级（2025 年 Miri PR #4314 升级后与 SB 齐平） [^29^] |
| 已证明的优化 | 多数优化已证，读-读重排因 stack hack 无法证明 [^14^] | Rocq 证明保留 SB 绝大多数优化 + 读-读重排合法 [^14^] |
| Miri 状态（2026-08） | 默认模型 [^30^] | 需 `-Zmiri-tree-borrows` 显式启用 [^30^] |

表 3-1 揭示一个容易被"54% 少拒绝"数字掩盖的事实：TB 并非 SB 的纯超集。两个模型各自放行对方拒绝的代码——SB 的"即时唯一"在 TB 中变成"激活写才唯一"，而 TB 对 two-phase borrow 的正确建模反过来拒绝了 SB 放任的别名。因此"从 SB 迁到 TB"不是单向删除 workaround 的过程，而是双向的语义重裁决。此外 UnsafeCell 精度一行说明两模型的已知差距在 2025 年后已被工程性抹平，剩余分歧集中在隐式写与子对象来源（subobject provenance）两处，这正是 3.1.2 节收敛谈判的标的物。

TB 的收紧面需逐条列出，因为它直接决定旧代码的命运。第一，SB 把 two-phase borrow 当裸指针处理、接受任意别名，TB 则要求激活写之后真正唯一[^14^]。第二，"先写裸指针、再创建引用"在 TB 下变 UB：`to.write(0)` 激活 two-phase 后再调用 `a.as_ptr()`（对整个 `self` 的隐式读）会把 `to` 冻结为只读，后续 `copy_nonoverlapping` 非法，而同一代码在 SB 下合法[^27^]。第三，protector 机制引入最反直觉的新 UB：作为函数参数传入的 `&mut`，在调用存续期内若既遭遇外来读又发生本地写（任意顺序）即 UB，哪怕该引用之后不再使用；Ralf Jung 预期 protectors 将是 TB 下"意外 UB 的主要来源"且"没有多少回旋余地"，因为它是支撑 LLVM `noalias` 的最低要求[^27^][^31^]。真实案例中，nalgebra 的 `MatrixViewMut` 子视图 SB 判 UB、TB 通过（nalgebra#1588），BTreeMap 中"为安抚 SB 而把引用转裸指针"的写法在 TB 下成为多余[^32^]。

#### 3.1.2 定案进程：Miri 旗标、UCG #573 与 #132898 悬案

截至 2026-08，Miri 中 SB 仍是默认模型，TB 需以 `MIRIFLAGS=-Zmiri-tree-borrows` 显式开启；README 将两者均标注为 Experimental，并警告最终模型"很可能比 Tree Borrows 更严格"——今天被 TB 放行的代码未来可能被判 UB[^30^]；而 UCG #573 的标题本身即"以便丢弃 Stacked Borrows"，说明 SB 同样在被讨论弃用[^33^]。TB 的调节旗标族（如 `-Zmiri-tree-borrows-implicit-writes`）可视为下述参数化收敛的预演[^30^]。2025 年 TB 在 Miri 中完成两项补课：UnsafeCell 字节级追踪默认开启（PR #4314），wildcard provenance 支持使 int-to-ptr 代码也能被检查[^29^]。

官方收敛方向由 UCG #573（2025-06-09，Ralf Jung 发起）确立：不再维护两个模型，而是以 TB 为骨架收敛为"单一模型 + 一组可调参数"，逐步加回 SB 的严格性——UnsafeCell 精度一项已解决，剩余最大未知项是 `&mut` retag 的隐式写[^33^]。该未知项与 UCG #584 的 `writable` 之争直接联动：LLVM 新增的 `writable` 属性允许编译器向引用参数插入投机写（speculative writes），若推广到所有函数则"基本排除 Tree Borrows 作为别名模型"；Ralf 2025-10 表态将开 t-lang 设计会议探口风，但截至 2026-08，#573 仍 open、无正式 FCP 决议，会议纪要亦未公开[^33^][^34^]。

与定案迟滞相关的是 rust-lang/rust #132898 这桩悬案：2024-11 报告，一段 SB 下合法的 two-phase borrow 代码在 `mir-opt-level=2` 下被 ReferencePropagation pass 误编译出 UB——该 pass 把一次 `SharedReadWrite` 裸指针访问重写为 Unique place 直接写，破坏了"two-phase 借用已为本次调用保留"的事实[^35^]。该 issue 标记 I-miscompile，截至 2026-08 仍 open 未修复；Ralf 指出"在 Tree Borrows 下该推理反而成立"，使此事故成为"编译器优化跑在语义规范之前"的标志性案例，也直接为 #573 的收敛提供了动机[^35^]。

#### 3.1.3 实务建议：过渡期的保守准则

在官方模型定案前，社区通行建议是同时以默认（SB）与 `-Zmiri-tree-borrows` 运行 Miri、令代码在两个模型下都通过[^32^]。落实到写法上有三条可操作的准则：其一，在任何首次写入之前先创建完全部裸指针与引用（"set up all your raw pointers before you start doing anything"），可同时规避 SB 的即时唯一性误报与 TB 的激活后冻结[^27^]；其二，函数存续期内不要用别 provenance 的指针触碰作为参数传入的 `&mut` 所指内存，以避开 protector 的外来读+本地写双禁忌[^31^]；其三，int-to-ptr 场景尽量采用 strict provenance API（Rust 1.84 稳定），而非依赖 Miri 的 wildcard 解释[^29^]。需要提示的是，"同时满足两模型"为社区惯例而非官方规定。

### 3.2 语义规范化工程

#### 3.2.1 MiniRust、desugaring 塔与规范双轨

别名模型只是 Rust 语义规范化的一块拼图。学术轨的核心是 Ralf Jung 发起的 MiniRust：一个以 specr 伪代码书写的可执行参考解释器，UB 即解释器逐步执行中遇到的非法状态；语言与内存模型通过无类型、面向字节的"内存接口"解耦，仓库内含基本内存模型与 Tree Borrows 内存模型两种实现[^36^]。MiniRust 已在反向塑造官方条文：它在两点上刻意比 Reference 少 UB（裸指针仅取地址不解引用、创建指向无效值的引用不总是 UB），由于 rustc 并未利用这些 UB，对齐属于"纯规范变更"[^36^]。2026-06，Nadrieril 发表规范愿景，提出三层架构：MiniRust 定义运行时语义（"接近成为 Rust 运行时语义的 source of truth"），其上以约 30 步的"desugaring 塔"把完整 Rust 逐层翻译到 MiniRust，再以 dictionary-passing 的 PolyMiniRust 处理泛型与 trait[^37^]。该愿景的未决问题同样坦率：规范"如何获得官方权威地位"尚无答案[^37^]。

工业轨方面，Ferrous Systems 与 AdaCore 于 2025-03 将 Ferrocene Language Specification（FLS）捐赠给 Rust 项目，2025-10-31 FLS 团队正式成立、从 spec 团队分拆建制；FLS 自我定位为描述 Rust"当前实现"（as-implemented）的行为、面向安全关键认证，而非 normative 的预期行为规范[^38^]。2026 年项目目标把两条轨道并列表述：Large 目标"Stabilize FLS Release Cadence"（含发布首个 rust-lang 自有版本），以及 T-opsem 牵头的"Normative Documentation for Sound unsafe Rust"——后者若落地，将首次给 sound unsafe 代码一份官方裁决基线[^39^]。两轨是描述性（FLS）与规范性（MiniRust/T-opsem）的互补；对实践者的含义是，今天依赖"约定俗成"上游行为的 unsafe 写法，将在 normative 文档发布后被重新裁决。

#### 3.2.2 BorrowSanitizer：LLVM 级的别名检测新路径

TB 的检查长期依赖 Miri 的解释执行，其性能开销使其难以进入 fuzzing 与常规 CI。BorrowSanitizer（CMU 团队，Ian McCormack 与 Molly MacLaren；Google 经 Rust Foundation 资助）提供了第二条路径：把 TB 检查做成 LLVM 级 sanitizer——"别名版 AddressSanitizer"。编译器以 `__rust_retag_reg`/`__rust_retag_mem` 两个 intrinsic 把 retag 信息保留到 LLVM 层，运行时采用 shadow stack 存 provenance（为 GC 铺路），核心为 fork 自 Miri TB 实现的 `#![no_std]` 库[^40^]。项目 2025-12 发 pre-RFC、2026-01 转为 MCP，2026-05-05 正式成为 2026 Rust Project Goal（#624，champion 含 Ralf Jung），2026-05-29 向 LLVM 社区发布实验性支持 RFC，远期目标是单一 `-Zsanitizer=borrow` 旗标[^40^][^39^]；截至 2026-03，Miri 别名测试套件已移植数百条、80% 通过[^40^]。其价值不止于速度：插桩发生在 LLVM 层，provenance 追踪可跨越 C/C++ FFI 边界，直接回应 Reference 关于"UB 影响整个程序、FFI 双向穿透"的规范警示[^16^]。已知取舍包括跳过赋值后的 retag（接受与 Miri 的精度差）、尚不支持 TLS 与全局变量[^40^]。

## 4. 生态全景（上）：动态检测与模型检查

第 3 章讨论了 Stacked Borrows（SB）与 Tree Borrows（TB）两种别名模型的语义分歧；本章考察把这些语义（以及更宽泛的 UB 定义）落到可执行检查的两条技术路线：以 Miri 为代表的动态检测，与以 Kani 为代表的模型检查。两者在"能检查什么"上呈互补结构，这一互补性是理解当前 Rust 验证工具栈的关键。

### 4.1 Miri 与动态 UB 检测

#### 4.1.1 Miri 能力矩阵与 POPL'26 实证

Miri 是 rust-lang 组织官方维护的 UB 动态检测器，本质是 Rust 抽象机的直接实现：它在 MIR（Mid-level IR）上逐语句解释执行，同时维护普通执行中不存在的状态——逐字节初始化标记、指针 provenance（来源）、基于 FastTrack 向量钟的数据竞争状态，以及 SB/TB 两套实验性别名模型的借用栈/树[^41^][^5^]。由于 MIR 保留完整类型信息，Miri 能检测 sanitizer 类工具无法覆盖的 UB 类别，如指针 provenance 错误与非法 `bool`/枚举判别值[^5^]。

**表 4-1 Miri 检测能力矩阵**（依据官方 README 与 POPL'26 论文整理，2026-08 口径）

| UB 类别 | 检测机制 | 状态 |
|---|---|---|
| 越界访问与 use-after-free | CompCert 式块模型内存，按分配界检查 | 稳定 [^41^] |
| 未初始化数据的非法使用 | 逐字节初始化标记 + `-Zstrict-init-checks` | 稳定 [^41^] |
| intrinsic 前置条件违规（如 `unreachable_unchecked`、重叠 `copy_nonoverlapping`） | 解释执行时逐调用检查 | 稳定 [^41^] |
| 对齐不足的访问与引用 | 类型化 MIR 上的对齐检查 | 稳定 [^41^] |
| 基本类型不变量违规（非法 `bool`、非法枚举判别值） | MIR 保留的 validity 不变量 | 稳定 [^41^] |
| 数据竞争与部分弱内存效应（原子读可返回过期值） | FastTrack 向量钟 + 随机调度多执行 | 稳定，但弱内存仅部分模拟 [^41^][^5^] |
| Stacked Borrows 违规 | 借用栈追踪（默认开启） | 实验性 [^41^] |
| Tree Borrows 违规 | 借用树追踪（`-Zmiri-tree-borrows`） | 实验性 [^41^] |
| 内存泄漏 | 程序退出时分配表审计 | 附加报告 [^41^] |

矩阵的稳定/实验分界值得注意：SB 与 TB 均标注为"实验性"，且 SB 仍是默认模型、TB 需显式开启——这意味着 Miri 报出的别名违规带有模型未定的前提，报错信息本身也附带"SB 规则仍是实验"的免责声明[^41^]。前六类检查的语义基线相对稳固，因为 POPL'26 论文将其锚定在"当前编译器实际依赖的全部假设"上（论文称 de-facto UB），而非某个尚不存在的形式规范[^5^]。

POPL'26 论文给出了迄今最大规模的实证：从 crates.io 下载量最高的 100,778 个库（覆盖全注册表约 180k 库的一半以上）出发，过滤后 59,136 个有测试的库中 51.8%（30,651 个）被 Miri 完整检查，**7.8%（4,595 个库）的测试触发了 UB**；测试级口径下 1,569,485 个测试中 70.3% 通过，整个实验消耗约 1.9 CPU 年（32 核机器运行 11 天；按硬件线程计，物理核口径约为其一半，此为本报告的换算推断）[^5^]。性能方面，论文微基准（计算密集负载，native 关全部优化）测得 Miri 比原生执行**慢 3,000–7,000 倍**，并明确"太慢以至于无法用于典型 fuzzing 配置"[^5^]。此处需作口径澄清：第三方资料常引用 10–50x 或约 100x 的开销（IN-COM 博客，二手来源，置信度低）[^42^]，这些数字来自真实测试套件的体感负载而非受控微基准，两者不可互换；本报告以论文一手数据为准，二手口径仅作负载敏感性的旁证。

对并发代码，Miri 以固定种子的伪随机调度解析非确定性选择，并支持多种子扫描（`-Zmiri-many-seeds`，默认 64 种子）：论文实测该模式对示例数据竞争的检出率约 90%，但对弱内存 bug 仅约 25%——这是 CI 中需要多种子矩阵扫描的定量依据[^5^]。

#### 4.1.2 局限与互补：FFI 盲区、弱内存与 sanitizer 体系

Miri 的局限被官方明确表述为三条。其一，动态检测的路径依赖："Miri 没找到 UB 不代表代码 sound"，它只能判定特定输入、特定调度下的单次执行[^41^]；第三方实验为此提供了注脚——对 27 个合成生命周期 bug，直接喂入触发函数则 27/27 检出，不给则 0/27[^43^]。其二，FFI（外部函数接口）盲区：Miri 不能执行外部 C 函数，POPL'26 实验中 21.7%（12,853 个）的库因此无法检查，且 OpenSSL、SQLite 等长尾 C 库"永远不会有 Miri 实现"[^41^][^5^]。其三，弱内存只模拟部分效应，非确定性程序只能随机探索而非完备枚举[^41^][^5^]。

围绕 FFI 盲区，CMU 的 MiriLLI（Miri 与 LLVM 解释器联合执行）在 957 个调用外部函数的库的 9,130 个测试中发现 **46 处 UB 或不良行为**（37 个库；最新 v6 版口径，早期 v3 版为 48 处/38 库）；按 v3 版的构成拆解，25 处位于 LLVM/C 侧、17 处位于 Rust 侧、6 处为错误绑定；90 个 SB 违规测试中 66% 在 TB 下不再违规，成为"TB 更贴合真实 FFI 代码"的重要实证[^44^]。其工程延续是 BorrowSanitizer（BSAN）：把 Miri 的 TB 借用追踪器移植为 LLVM 编译期插桩 sanitizer（`cargo bsan`），2026-05 已向 LLVM 社区提交 upstreaming RFC 并列为 Rust 官方 2026 项目目标，目标是以接近 sanitizer 的性能覆盖多语言应用并兼容 fuzzing[^40^]。弱内存方向上，ETH 的 Miri+GenMC 集成（GenMC 无状态模型检查器枚举全部并发执行，Miri 逐条做全 UB 检查，支持 RC11 与 SC 两种内存模型）已开始上游化，但 Miri 第一作者明确其"高度实验性、慢、需定制构建"[^29^]；独立路线 RUSTMC（2025-02）则把 GenMC 直接扩展到 Rust 的 LLVM IR，可检查含 C/C++ FFI 依赖的并发程序[^45^]。

在此之下是一个分层互补的工具谱系：Loom（tokio-rs）是并发排列测试的事实标准，但官方明确其"既不 sound 也不 complete"——SeqCst 被当作 AcqRel 处理（可能误报）、不探索 load buffering（可能漏报）[^46^]；AWS 的 Shuttle 则以随机调度换可扩展性[^47^]。LLVM sanitizers（ASan/TSan/MSan/LSan）经 `-Zsanitizer` 可用但仍是 nightly 不稳定特性，稳定化已在官方路线图（先 ASan/LSan，MSan/TSan 列入 2026 项目目标）[^48^]；cargo-careful 以带 debug assertions 的标准库加额外运行时检查填补"普通测试与 Miri 之间"的档，速度快且支持任意 FFI，但覆盖面小得多[^49^]。工程实践已收敛为分层 CI 范式：Microsoft oxidizer 的 PR 门禁是最完整的公开实例——Miri 以 SB/TB/strict-provenance/many-seeds 矩阵运行（"每个变体各挡一类 UB"），cargo-careful 兜底，Loom 专项并发，Bolero 限时 fuzz[^50^]；Qiskit 的规范则是"新增 unsafe 必须配 Rust 侧测试、Miri 作为 UB sanitizer 进 CI"[^51^]。

### 4.2 Kani 与模型检查产业实践

#### 4.2.1 架构（MIR→GOTO→CBMC）与 AWS 生产案例

Kani 是 AWS 主导的 Rust 模型检查器，也是目前产业部署最深的 Rust 验证工具。架构上它复用整个 rustc 前端、替换代码生成后端：kani-compiler 经 `rustc_private` 钩在 MIR 生成之后，做 MIR-to-MIR 变换（可达性分析、契约插桩、stubbing、安全检查插入），再翻译成 CBMC 的 GOTO 程序，由 CBMC 符号执行、展开循环、编码为命题公式交 SAT/SMT 求解器（默认 MiniSat，可选 Kissat/Z3/cvc5/Bitwuzla）[^52^]。选择 MIR 而非 LLVM IR 是关键决策：MIR 保留单态化类型信息、枚举判别式布局与 Rust 有效性不变量，使 Kani 零注解即可自动检查三类属性——UB 缺席（悬垂解引用、对齐错误、非法判别值）、panic 缺席（溢出、除零、越界）与资源属性[^52^]。向无界验证延伸的阶梯是规约语言：函数契约（requires/ensures/modifies）、循环契约（循环体在单次查询中只执行两遍，验证时间与迭代次数解耦）、量词与函数 stubbing[^52^]。

生产证据链完整。Firecracker 自 2022 年起每次代码变更跑 Kani CI：rate limiter 发现 5 个 bug（最严重者为舍入误差，允许 guest 超出规定 I/O 带宽最多 0.01%），VirtIO 栈发现 1 个可致启动崩溃的 bug（guest 可构造与 MMIO 区域部分重叠的 virtqueue）[^53^]。s2n-quic 通过 Bolero 框架让同一 harness 既是 fuzz 测试又是 Kani 证明：`try_fit` 的一处边界 bug 在 libFuzzer 跑 16,777,216 次（超 10 分钟）无果后，被 Kani 在 20 秒内命中——该 bug 位于一字节与两字节整数编码的稀疏边界区，覆盖率引导的 fuzzing 无梯度可达[^54^]。Hifitime 从 11 个 panic-freedom harness 演进到 153 个契约证明，契约阶段新发现 6 个 bug（含违反 Rust 标准库自身 Eq/Ord 契约的语义错误），规约由 AI 助手起草且 3 个 AI 生成的错误契约全部被 Kani 自身拦截[^52^]。ASE 2026 论文自述四个生产代码库（Firecracker、s2n-quic、Hifitime、Cedar）合计发现 **11 个测试与 fuzz 漏掉的真实 bug**[^52^]；2026-10-27 直读论文 Table 2 与 §5.1，其分项为 s2n-quic 2（try_fit 断言、包号解码溢出）、Firecracker 2（rate limiter 舍入、VirtIO 来自 guest 的 panic）、Cedar 1（contains_at_least_two）、Hifitime 6，合计 11，可自洽对账。上文 Firecracker "5+1"取自 2023 年官方博客[^53^]，而论文正文只写"rate-limiter 中发现数个 bug"并在 Table 2 中仅列 1 行舍入误差，二者计数口径不同（博客按单个缺陷计、论文表按缺陷类别列示，此解释为本报告推断，论文未明说）；s2n-quic 论文列 2 个，上文提及的 try_fit 仅是其一。引用总数请以论文 11 个为准，分项以 Table 2 为准。需要修正一个常见提法：s2n-tls 并非 Kani 案例——s2n-tls 是 C 实现（用 CBMC/SAW 验证），Kani 案例是 Rust 实现的 s2n-quic[^55^]。

#### 4.2.2 verify-rust-std 数据口径、ESBMC 接入与能力边界

verify-rust-std 战役（2024-11 AWS 与 Rust Foundation 发起）是 Kani 规模化的主要载体，但其 harness 数字存在三个不可混用的口径，本报告按交叉验证裁定分列：**16,748** 是 Autoharness 自动生成的 harness 总量（其中 11,970 个通过 Kani 支持的 UB 类别验证，4,645 个针对 unsafe 函数、1,126 个针对 unsafe 之上的安全抽象），经并行化与增量缓存 3.97x 加速后每次代码变更全量运行（CI 约 69 分钟）[^56^][^52^]；**725** 是官方论文口径的手工编写 harness（694 个带函数契约，2025-10 快照、项目前 16 个月累计；2026-10-27 已直读 [^56^] §4 核对，725 并不出现在 Kani 论文 [^52^] 中，16,748 则同见于 [^52^] Table 1 与 §5.3，另 [^56^] 载明其中 11,970 个验证通过、989 个函数带契约=295 自动+694 手工）[^56^]；**1,369** 出自第三方 safety-tags 论文的 2026-04 快照[^57^]。三者分别对应"自动生成总量 / 手工·官方时点 / 手工·第三方时点"，引用时须标注。自动化的覆盖缺口同样被量化：17,207 个被跳过的函数中，泛型单态化占 9,635 个（56%）——Autoharness 无法为未实例化的类型参数合成输入，这是最大的未验证类别[^56^]。

**表 4-2 Rust 模型检查工具对比**（2026-08 口径）

| 工具 | 前端 / IR | 求解后端 | 并发支持 | 别名（SB/TB）建模 | 产业状态 |
|---|---|---|---|---|---|
| Kani | MIR → GOTO [^52^] | CBMC（SAT 默认，可选 SMT） [^52^] | 不支持（告警后按顺序语义编译） [^58^] | 不建模（自认是 unsafe Rust 最主要 UB 类别的缺口） [^52^][^58^] | AWS 全职团队；Firecracker/s2n-quic/std CI；月发布 [^52^] |
| ESBMC（经 Goto-Transcoder） | 复用 Kani 的 GOTO 输出转 ESBMC GBF [^4^] | ESBMC（k-induction、增量 SMT、context-bounded 并发） [^4^] | 后端支持，受 Kani 前端限制 [^4^] | 不建模 [^4^] | 已进 verify-rust-std CI 与 Approved Tools；计划成为 Kani 可选后端 [^59^] |
| RUSTMC | LLVM IR（可含 C/C++ FFI） [^45^] | GenMC（TruSt DPOR 无状态模型检查） [^45^] | 完备枚举（无界循环除外） [^45^] | 不建模 | 学术原型（RHUL，2025-02） [^45^] |
| Miri+GenMC | MIR（Miri 作 GenMC 解释前端） [^29^] | GenMC（RC11/SC 内存模型） [^29^] | 完备枚举 [^29^] | 继承 Miri 全部 UB 检查（含 SB/TB） [^29^] | 高度实验性，需定制构建，上游化进行中 [^29^] |

对比可见当前格局的两个结构性特征。其一，Kani 生态走的是"位精确有界模型检查 + 契约阶梯"路线，在顺序代码的功能与安全属性上证据最强，但别名与并发是其自认的两个最深缺口：Kani 官方文档明示不检测数据竞争、不跟踪引用生命周期（即不建模 SB/TB 别名规则）、transmute 非法值只做 best-effort，遇并发代码告警后按顺序语义编译[^58^]；verify-rust-std 中要求证明无数据竞争的挑战 #7（原子类型）与 #27（Arc）截至 2026-08 均仍 Open[^4^]。其二，并发模型检查的三条路线（ESBMC 后端复用、RUSTMC 的 LLVM IR 路线、Miri+GenMC 的 MIR 路线）均未达到生产可用，这意味着"Miri 管别名、Kani 管功能属性"的互补分工在中期内仍是从业者的实际基线——任何"已验证"声明都应附保证清单，其语义天花板是"无 panic/无越界/契约成立"，而非"无 UB"。

ESBMC 的接入路径值得单独记录：它不经 Rust 前端，而是由 Goto-Transcoder（一个形式化统一 CPROVER 工具链内部表示的博士项目）把 Kani 输出的 CBMC GBF 转为 ESBMC GBF，从而引入 k-induction 与增量 SMT 求解；该工作流已在 verify-rust-std CI 上线、列入官方 Approved Tools 并获挑战赛奖金，官方计划是使其成为 Kani 的可选后端，与 Kani 里程碑中"新增一种模型检查引擎"的路线图互为印证[^59^][^4^]。截至 2025-10，goto-transcoder 尚未独立解决任何挑战，其意义目前更多在于验证后端多元化而非能力增量[^4^]。

## 5. 生态全景（下）：演绎验证、静态分析与供应链审计

上一章讨论的 Miri 与 Kani 分别在动态执行语义与有界模型检查层面拦截 UB；本章考察保证更强、注解成本也更高的演绎验证（deductive verification）与细化类型（refinement types）工具链，面向全生态普查的静态 bug 查找器，以及把"依赖是否可信"管理为工程流程的供应链审计层。三者的共同主题是保证强度、自动化程度与可持续维护性之间的取舍。

### 5.1 演绎验证与细化类型

#### 5.1.1 六工具横评：Prusti、Creusot、Verus、VeriFast、Flux、Aeneas/Charon

截至 2026 年中，演绎验证阵营可概括为"一超四强一管道"。**Prusti**（ETH Zurich，Viper 后端）正经历 Place Capability Graphs（PCG）架构换代：PCG 论文报告在 top-500 下载量 crate 上对 97.7% 的函数（118,483/121,271）在所有程序点成功生成模型，失败类别几乎全部是裸指针操作与内联汇编[^60^]。引用此数必须注意口径：97.7% 是 PCG 分析库的建模覆盖率，不等于 Prusti 端到端验证覆盖率；且未覆盖部分恰是 unsafe 指针——标准库验证挑战的官方报告因此明确将 Prusti 排除在适用工具之外[^4^]。**Creusot**（Inria，Why3/Coma 后端）正从 safe-only 翻身：2025 年引入 Verus 开创的线性 ghost 类型以验证底层指针操作代码，2026-01 的 0.9.0 迈出并发验证第一步（Iris 式 `AtomicInvariant`，暂仅顺序一致性），2025-09-16 向 verify-rust-std 提交接入申请（issue #493），按 2026-03 论文口径仍在审批中、未列入 Approved Tools[^61^][^56^]；0.9.0 等进展见[^62^]。

**Verus** 是牵引力最强的一极：OSDI 2024 三篇 Jay Lepreau 最佳论文中两篇（验证 K8s 控制器活性的 Anvil、发现 AMD SVSM 机密性缺陷的 VeriSMo）基于它，Asterinas 内核用其验证页表与内存管理子系统[^63^][^64^]；PLDI 2026 的 VerusBelt（杰出论文+杰出 artifact 双料，Iris/Rocq 机械化）为其重要子集给出首个语义 soundness 证明，但 ghost-code erasure 与 Z3 仍在 TCB 内[^65^]。代价同样具体：SOSP'24 Verus 论文摘要自述其案例系统合计 6.1K 行实现、31K 行证明，聚合证明比约 5.1:1（比值为本报告按两个行数相除得出，论文并未直接给出 5:1；Kani 论文亦以"约 5 行证明对 1 行实现"转引该数据）；分项差异很大，如页表 400 行代码配 5,329 行证明（13.3:1）、mimalloc 4.3、日志存储 3.9（2026-10-27 已直读原文 PDF）[^160^][^52^]；工具链快速演进还导致证明脆性[^156^]。**VeriFast**（KU Leuven）定位最"unsafe-native"：以分离逻辑模块化符号执行直接验证 unsafe 代码的 UB 缺席与模块 soundness，是 std 挑战中唯一能处理链表类无界指针属性的工具（Challenge 5 直接验证 19 个函数），截至 2025-10 的 9 个被接受解中 2 个出自它[^66^][^56^]；其 soundness 是条件性的（不完整检查 Tree Borrows 式可变引用别名规则），2026 年的 Foundational VeriFast 以生成 Rocq 证书回应这一短板，但实现尚 minimal[^67^]。

**Flux**（UCSD/IMDEA 等）以细化/liquid 类型换取最低注解成本：PLDI 2023 摘要报告相对 Prusti 基准规约行数减半、验证时间降一个数量级、循环不变量注解开销从最高 25%（均值 9%）降为零（按交叉验证以摘要口径为准）[^68^]；它已进 std 挑战 CI 但截至 2025-10 尚未解题，unsafe 支持有限——不能追踪经指针写入的值[^4^]。**Aeneas/Charon** 走"功能化翻译"管道：Charon 把 MIR 转为借用显式的 LLBC，Aeneas 翻译到 Lean 4/Coq/F*/HOL4 做交互式证明，只支持 safe 顺序 Rust（分离逻辑扩展在做）；其最大工业背书是微软 SymCrypt——被证明的 ML-KEM/SHA-3 代码已运行于 Windows Insider builds，规模约 5,529 行 Rust 对 58,377 行证明（约 10.6:1，该比例为该案例单一来源口径，宜作量级参考、不宜外推），人力成本为六工具中最高一档[^69^][^70^]。

| 维度 | Prusti | Creusot | Verus | VeriFast | Flux | Aeneas/Charon |
|---|---|---|---|---|---|---|
| 方法/后端 | 演绎验证，Viper→Z3 [^60^] | 演绎验证（prophecy+FOL），Why3 [^61^] | SMT 演绎+线性 ghost，Z3 [^63^] | 分离逻辑符号执行 [^66^] | 细化/liquid 类型 [^68^] | 功能化翻译→Lean/Coq/F*/HOL4 [^69^] |
| unsafe 支持 | 基本无（PCG 失败类别即裸指针） [^60^] | 2025 新增（线性 ghost） [^61^] | 强（proof-oriented 类型） [^65^] | 最强"unsafe-native" [^66^] | 有限（不能追踪指针写入） [^4^] | 无（扩展在做） [^69^] |
| 自动化程度 | 高 | 高 | 中高（proof 块+SMT） | 低-中（手写注解） | 最高（循环不变量自动推断） [^68^] | 低（约 10.6:1 证明比） [^70^] |
| 学习曲线 | 中 | 中 | 中 | 陡（分离逻辑） | 最平缓 | 最陡（证明工程） |
| std 挑战状态 | 官方明示不适用 [^4^] | 审批中（2025-09-16 提交申请） [^61^][^56^] | 审批中（2026-03 论文口径；2025-10 口径未列入） [^56^] | 已批+在 CI；2/9 接受解 [^56^] | 已批+在 CI；0 解 [^4^] | 未参与 |
| 学术地基 | PCG（OOPSLA 2025） [^60^] | RustHornBelt（PLDI 2022 杰出论文） | VerusBelt（PLDI 2026 双杰出） [^65^] | Foundational VeriFast（2026，进行中） [^67^] | PLDI 2023 [^68^] | ICFP 2022/2024 [^69^] |
| 维护状态（GitHub 实测 push） | 2026-07-30 [^71^] | 2026-07-31 [^71^] | 2026-08-02 [^71^] | 2026-05-10 [^71^] | 2026-08-01 [^71^] | 2026-08-01 [^71^] |

横向读表可得三条结构性判断。其一，在这六个样本中，unsafe 支持与自动化程度大体呈负相关（仅为六样本的归纳，Aeneas 即反例：unsafe 支持缺失而自动化程度同样低）：最"unsafe-native"的 VeriFast 注解成本最高，最自动化的 Flux 恰恰不能推理指针写入，Verus 以"用 proof-oriented 类型重写代码"换取中间点——std 挑战中 VeriFast 已解链表题而 Verus 尚在审批队列，正是这一取舍的工程后果。其二，六者维护全部活跃（最近 push 均在 2026-05 至 2026-08），与 5.2 节第一代学术 bug finder 的集体老化形成鲜明对照。其三，std 挑战赛正成为事实上的能力校准器：宣传定位与实际解题之间存在可观察的差距（Flux 在 CI 而零解、Verus 系统案例成熟而审批未过），选型应以解题记录而非论文声明为准。

#### 5.1.2 选型决策框架

沿 unsafe 支持度、自动化程度、学习曲线、维护状态四个轴，给出分层建议。**新项目、以 safe 代码为主**：从 Clippy lint 基线（5.2.2 节）起步，轻量安全属性与数值界用 Flux（学习曲线最平缓、循环不变量零注解）[^68^]，深度功能正确性再升级至 Prusti 或 Creusot。**含 unsafe 的库**：直接注解真实 unsafe 源码选 VeriFast，能接受以 proof-oriented 类型重写且需并发支持选 Verus；两者都应与 Miri 互补而非替代[^65^][^66^]。**安全关键组件（密码学、认证场景）**：Aeneas→Lean 4 管道提供最强的 foundational 保证，SymCrypt 案例给出可复用范式，但须为约 10 倍于代码量的证明劳动做预算[^70^]。**供应链治理**：演绎验证不解决"信任上游"问题，转向 5.3 节审计工具栈。跨场景通用判据：优先选择已进 verify-rust-std CI 或有解题记录的工具，并把"是否锁定 nightly、维护方是学术团队还是产业实体"作为与能力同权的指标。

### 5.2 bug 查找与静态分析

#### 5.2.1 第一代学术工具兴衰与 RAPx 的例外

**Rudra**（SOSP'21，Georgia Tech）是该品类参照系：以污点启发式检测三类模式，6.5 小时扫完当时全部 crates.io（约 43k 包），发现 264 个新内存安全 bug、对应 76 个 CVE，覆盖当时 RustSec 内存安全条目的 51.3%[^72^]。但后续独立评估揭示明显局限：2021 年后 transmute 从 MIR terminator 降级为 statement，使 Rudra 对类型混淆 bug 实质失效[^73^]；EASE 2026 复刻研究将其现代化后在约 2 万个含 unsafe 的 crate 上产出 4,879 条警告，人工标注显示原始输出精度仅 25.6%（1,247 真阳、3,632 误报）——注意这是 2025 年生态上复刻版的口径，非 2021 原论文数字[^74^]。Rudra 仓库于 2026-04-02 正式归档[^75^]。同代的 **MirChecker**（CCS'21，作者自报误报率 95.1%）最后功能提交停在 2024-05，被 Yuga 评为与当前工具链不兼容、27 个合成 bug 检出为零[^43^]；Meta 的 **MIRAI** 于 2024-08-22 归档，但 Endor Labs 在归档前一天 fork 接手、维护至 2026-05 仍有提交——按交叉验证裁定，"MIRAI 已死"不成立，准确表述是"换了产业托管方"[^76^]。早衰根因是系统性的：深度耦合 rustc 私有 API 与特定 nightly，编译器一演进即失效；Charon 式"稳定 IR 抽象层"与 Miri/Clippy 式"入树随发布"是两条被验证的解药[^77^]。例外是**复旦大学** Artisan-Lab（徐辉团队，按交叉验证裁定为复旦）的 **RAPx**：整合 SafeDrop/RCanary 路线并新增 Z3 契约验证，2026 年迁入 safer-rust 组织后六周发版 15 次（0.7.30，2026-07-29），自定位为"AI 生成 Rust 代码的护栏"[^78^]。理论前沿上，RUXt（ECOOP'25）以不正确性分离逻辑换取"报告即真阳"的无误报保证，但仅有小模型原型且无法检测别名层 UB[^79^]。

#### 5.2.2 Clippy lint 族与 CodeQL/Semgrep 的 GA 现状

Clippy/rustc lint 体系已成 unsafe 卫生基线。截至 2026-08 抓取的官方文档（847 个 lint）中，unsafe 相关 lint 分三类[^80^]：文档注释类——`missing_safety_doc`（style 组，默认 warn）要求公开 unsafe fn 带 `# Safety` 文档，`undocumented_unsafe_blocks`、`multiple_unsafe_ops_per_block` 等 restriction 组四件套默认 allow、需显式开启；误用检测类——`not_unsafe_ptr_arg_deref`、`wrong_transmute`、`unsound_collection_transmute` 等 correctness 组默认 deny；以及 rustc 侧的 `unsafe_op_in_unsafe_fn`（Rust 2024 edition 起默认 warn）与 `static_mut_refs`（2024 edition 默认 deny）[^81^]。Wasmtime、heapless 与 Linux 内核的 Rust 实践均在推动 restriction 组 lint 的采用[^80^]。

通用 SAST 方面，**Semgrep** 的 Rust 支持已升至官方文档的 Generally available（跨函数数据流、40+ Pro 规则，Supply Chain 对 Cargo 亦 GA），GitLab 2026-07 正将其纳入自家 SAST 分析器[^82^]；**GitHub CodeQL** 的 Rust 支持 2025-07-01 公开预览、2025-10-27 GA，覆盖 OWASP Top 10 除 A06 外全部类别并内置 30+ 主流 crate 模型[^83^]。两者的能力边界一致且重要：面向注入、加密误用等通用漏洞模式，不做 Rust 特有的别名/soundness 层面 UB 分析——通用 SAST 与学术 unsafe 分析器能力正交[^82^][^83^]。

### 5.3 供应链审计

#### 5.3.1 cargo-geiger 的正确解读与 cargo-audit/RustSec 基线

**cargo-geiger** 统计 crate 及其传递依赖中 `unsafe` 关键字使用量，以 🔒/❓/☢️ 三符号标记；其 README 明示该工具"不直接判断代码是否真正不安全"，定位是为人工审计提供统计输入[^84^]。两类误读被社区反复纠正：把高 unsafe 计数当作"有漏洞"，以及把"全 safe 徽章"当作可信证明——kornelski 在官方 Discussion 中指出，恶意代码可经 proc-macro、build.rs 等通道绕开 unsafe 关键字，甚至刻意避开 unsafe 以骗取徽章，"safety ≠ security"[^84^]。正确用法是把输出当审计分诊地图（triage map），且其语法扫描口径本身存在宏展开计数不准等已知缺陷[^84^]。

**cargo-audit + RustSec Advisory Database** 是依赖漏洞扫描基线。RustSec 把无已知利用路径的 soundness 缺陷制度化为一等信息级公告（`informational = "unsound"`），cargo-audit 可用 `--deny unsound` 升级为 CI 失败[^85^]。MSR 2026 的 RustXec 数据集论文给出统计：2021-01 至 2025-04 共收集 515 条 RustSec 公告条目，其中标注为 unmaintained 117 条、unsound 89 条、重复 10 条，剔除这 216 条后余 299 条（515−216=299，与论文原文逐项对得上）——即 515 已包含 unsound 与 unmaintained 两类，unsound 类占 89/515≈17.3%（2026-10-27 已对论文原文核对；此前 89/721≈12% 的并列口径以 515+89+117 为分母属误算，已删除）[^86^]；2025–2026 年 "Unsoundness in …" 条目明显加速，anyhow、cxx、lru 等顶级 crate 亦在其列，说明主流库的 soundness 公告是持续性产出，审计不是一次性工作[^85^]。

#### 5.3.2 cargo-vet 机构互导网络 vs cargo-crev；实证缺口与 AI 入场

**cargo-vet**（Mozilla）是唯一形成真实网络效应的审计记录工具：官方 registry.toml 截至 2026-08（2026-10-27 复核仍为 9 家）收录 actix、ariel-os、Bytecode Alliance、Embark、Fermyon、Google、ISRG、Mozilla、Zcash 共 9 家机构审计集，导入刻意不可传递以保持信任关系直接[^87^]。杠杆可量化：Zcash 系项目导入七方审计集后，下游项目 Argos 的 618 个传递依赖中 142 个（约 23.0%）完全审计且全部来自上游导入；导入前覆盖率起点（"从 0"）无证据，且该案例仅见 Argos 一份项目自述文档（THREAT_MODEL，单一来源）[^88^]。对照之下，**cargo-crev** 的个人密码学 web-of-trust 路线虽仍发版，但网络效应从未形成：S&P 2024 实证中它甚至未进入被使用的审计工具列表[^9^]。该研究同时给出核心缺口数据：**160 名问卷调查受访者中 88% 审计依赖 unsafe 使用的频率不足一半，仅 51% 用过自动化审计工具，其中 cargo-audit 63%、cargo-geiger 22%、cargo-vet 仅 7%**[^9^]。方法论层面，ESOP 2026 的 Cargo Scan 用副作用分析把人工审计面压至中位数 0.2% LoC（top-10K crates 中 3,434 个可判 pure），并指出 `#![forbid(unsafe_code)]` 的 axum 仍传递依赖含 unsafe 的 hyper——信任记录无法表达上下文相关的安全性[^89^]。2025–2026 的最新变量是 AI 审计工具入场：Trail of Bits 发布官方 rust-review skill，草根 skill 与 agentic harness（以 Miri/fuzz 裁决 AI 结论）构成两条路线，但 AI 结论可靠性仍须确定性工具兜底[^90^]。

| 工具 | 定位 | 机制 | 关键数据/采用证据 | 状态 |
|---|---|---|---|---|
| cargo-geiger | unsafe 面盘点（分诊地图） | 语法级 unsafe 计数 [^84^] | 使用率 22%（用过审计工具者中） [^9^] | 维护放缓（[^91^] 2026-06 口径末次提交 2025-08-31；2026-10-27 查 GitHub 主分支最新提交为 2026-10-12 "Release 0.14"，已恢复发版） [^91^] |
| cargo-audit + RustSec | 已知漏洞/unsound 扫描基线 | 对照 Advisory DB；`--deny unsound` [^85^] | 515 条公告（含 89 unsound、117 unmaintained、10 重复；2021.01–2025.04） [^86^] | 活跃，使用率 63% [^9^] |
| cargo-deny | 策略引擎（licenses/bans/advisories/sources） | 单一 deny.toml 统一策略 | 使用率 31%；常替代 cargo-audit [^9^] | 活跃（2026-06 提交） [^91^] |
| cargo-vet | 人工审计记录与机构共享 | audits.toml 导入、不可传递、delta 审计 [^87^] | 9 家机构互导；一次导入覆盖 142/618 crate [^87^][^88^] | 维护中、节奏缓慢；使用率仅 7% [^9^][^91^] |
| cargo-crev | 个人密码学 web-of-trust 评审 | 分布式可加密验证评审 | 未进入实证使用工具列表 [^9^] | 仍发版（v0.27.1）但采用停滞 [^92^] |
| cargo-semver-checks | 升级引入新 unsafe 义务的拦网 | rustdoc JSON+Trustfall 查询 | 177 个 lint；`#[target_feature]` 研究反哺语言级 unsoundness 修复 [^93^] | 活跃（2026-05 提交） [^91^] |
| Cargo Scan | 交互式审计面缩减 | 副作用分析跨 crate 追踪 | 审计面中位数 0.2% LoC；3,434/10K crate 判 pure [^89^] | 研究原型，商业试用中 [^89^] |
| AI 审计工具 | 审计工作流封装 | LLM skill/agentic harness+Miri/fuzz 裁决 | Trail of Bits rust-review（2026-01）；草根 skill 质量未经独立验证 [^90^] | 新兴（2025–2026），待核实 [^90^] |

纵向读表，分层与断层同样清晰。基线层（audit/deny）采用率最高，是任何项目的最低配置；盘点层（geiger）语义误读风险最大，其价值取决于使用者是否理解"计数≠风险"；记录层呈现 vet 与 crev 的鲜明对照——机构级直接信任（9 家互导、可量化的导入杠杆）跑通了网络效应，个人 WoT 则未能形成网络效应（归因于密钥与信任图的维护摩擦，仅见博客评论、属推断而非实证[^92^]），这与 CRA 等机构合规时代"审计责任主体是组织"的粒度一致。断层在中段：vet 使用率仅 7% 与 88% 受访者审计不足互为印证，瓶颈不在工具供给而在审计劳动供给；Cargo Scan 的 0.2% 中位数审计面与 AI 工具的"Miri/fuzz 裁决"范式是 2026 年针对这一瓶颈的两条最有前景的回应，但前者仍是研究原型、后者可靠性未经独立验证，短期内人工审计不可绕过。

## 6. 内核与系统级实践

第 4–5 章评估了用户态的验证与审计工具链，本章转向 unsafe 工程纪律最严苛的落地场景：Linux 内核与系统级软件。前述"证明义务"框架在此呈现为最完整的工程形态——集中的抽象层、强制的 SAFETY 注释与编码进类型的不变量；而首个公开分配 CVE 的内核 Rust 缺陷的复盘，则检验了这套纪律在并发场景下的真实边界。

### 6.1 Rust for Linux 的 unsafe 工程方法论

#### 6.1.1 实验收官与三层抽象架构

2025-12-10，东京 Linux 内核维护者峰会以"零反对"达成共识：内核中的 Rust 不再是实验，而是内核的核心组成部分；Rust for Linux 负责人 Miguel Ojeda 随后以文档补丁"rust: conclude the Rust experiment"确认此事，同时声明这不意味着所有配置、架构与工具链组合均已就绪[^94^]。制度背书之前已有生产事实：基于 6.12 的 Android 16 设备出厂即运行 Rust 重写的 ashmem 分配器，Ojeda 在 LPC 2025 明确将"数百万用户"列为申请移除实验标签的依据[^95^]。

unsafe 治理的制度核心是三层架构：safe 叶子驱动 → `rust/kernel/` 抽象层 → bindgen 自动生成的 bindings，官方文档明确规定叶子模块不得直接使用 C bindings[^96^]。由此所有与 C 的直接交互被压缩进 `rust/kernel/`，逐行评审并逐行配 `// SAFETY:` 注释；只要抽象层 sound（健全），上层 safe 驱动无法引入 UB。配套纪律包括 `unsafe_op_in_unsafe_fn` 方言（unsafe 函数体内仍需显式 unsafe 块，为每个 UB 风险点提供独立注释锚点）、unsafe 函数必须以 `# Safety` 小节记录前置条件；规范强调注释的关键价值在于证明"没有额外的隐式约束"[^97^]。不变量还被编码进类型：`ARef`/`AlwaysRefCounted` 将 C 侧 get/put 引用计数配对转化为所有权语义（Clone 即 inc_ref、Drop 即 dec_ref），泄漏或重复释放变成类型错误[^98^]。学术界正推动该实践形式化：2026-01 的 Pre-RFC "Rust Safety Standard" 以 std 与 RFL 为审计对象，点名其类型不变量实践（List、ListLinks、Cursor 等）[^99^]。

这套集中化策略的量化证据来自 ACSAC 2024 论文对三个最完整驱动分支的逐行统计[^1^]：

| 代码位置 | 驱动/分支 | 总行数 | unsafe 行数 | unsafe 占比 |
|---|---|---|---|---|
| 驱动自身 | AGX | 15069 | 114 | 0.76% [^1^] |
| 驱动自身 | NVMe | 1758 | 27 | 1.54% [^1^] |
| 驱动自身 | Binder | 4263 | 145 | 3.4% [^1^] |
| kernel crate | NVMe 分支 | 7179 | 659 | 9.18% [^1^] |
| kernel crate | Binder 分支 | 9116 | 884 | 9.7%（2026-10-27 已对 ACSAC 2024 论文 Table 4 原文核对：9116 行、884 行 unsafe、9.7%；884/9116=9.70%，此前底稿的 9136/834/9.13% 为转录错误） [^1^] |
| kernel crate | AGX 分支 | 9428 | 915 | 9.71% [^1^] |

表中约一个数量级的反差与该架构设计相符（AGX 驱动自身 0.76% 对其 kernel crate 分支约 9.7%，约 12 倍；NVMe 与 Binder 的差距更小）：三个驱动自身 unsafe 占比均不高于 3.4%，而共享的 kernel crate 约为 9.2%–9.7%——unsafe 并未消失，而是集中到可集中审计的 kernel crate。需注意，三个分支的 kernel crate 规模并不相同（7,179、9,116、9,428 行），表明该表面随分支与驱动需求而增长，"固定大小、不随驱动数量增长"无法由此表支持。Binder 占比偏高主要源于其需对接仍为 C 实现的 binderfs。需注意口径边界：该数据为 2024 年论文快照，统计的是 unsafe 块行数而非风险权重；Google 报告的 Android 平台"约 4% 代码位于 unsafe 块内"是另一口径，不可混用[^2^]。论文同时批评安全契约仅以非正式注释记录、未使用形式化规约语言——这正是上述 Pre-RFC 与验证工具介入的切口。

#### 6.1.2 路线图：稳定化清零与 GCC 侧双轨

LPC 2025（2025-12）公布的 2026 年预期包括（截至 2026-08 底稿未跟踪其兑现情况）：内核不再使用任何 unstable 语言特性（当前仅剩 arbitrary_self_types 与 derive_coerce_pointee 两个，且仅其一允许全局使用）；推进 field projections 等新特性（已成独立 Rust project goal）；rustc_codegen_gcc 进入 Rust CI 并构建 Rust for Linux；gccrs 首次构建 kernel crate 与内核模块[^95^]。gccrs 已把"Rust for Linux compiler"列为三大里程碑之一，其内核议题已被 RustConf 2026 接受；月报特别强调 Drop 语义对内核的关键性（互斥锁等类型的 Drop 含复杂副作用）[^100^]。主线工具链基线为 Rust 1.85.0 + bindgen 0.71.1，下限策略跟随 Debian stable[^95^]。

### 6.2 CVE-2025-68260 深度复盘

#### 6.2.1 技术根因与时间线

CVE-2025-68260 是（截至 2026-08 锚点）主线内核首个公开分配 CVE 的 Rust 代码缺陷，位于 rust_binder（6.18 合入主线，Android 16 首个生产用户）的 `Node::release`。被攻破的 SAFETY 注释论证了一个二分："`NodeDeath` 只会被插入其属主的 death list，因此它要么在此链表、要么不在任何链表"，据此对侵入式链表 `remove` 的并发独占性作出保证[^3^]。但 `Node::release` 引入了注释书写处不可见的第三态——元素在（栈上）外部链表：

```rust
// Node::release 的缺陷模式（简化）
lock();
local_list.append(&mut death_list); // 持锁搬空到栈上链表
drop(lock);
for n in local_list.iter() { ... }  // 放锁后元素 prev/next 仍活跃
// 另一线程此时对原链表执行 unsafe remove(self)，
// 双方并发触碰同一组 prev/next → 数据竞争、指针损坏
```

持锁搬空、放锁遍历，与另一线程基于"元素在原链表故持锁独占"判断而执行的 unsafe remove 并发触碰同一组 prev/next 指针，造成内存损坏与内核崩溃（arm64 下游 6.12-android16 内核日志显示 rust_binder 工作队列中的 paging request 错误）[^3^]。修复不是加锁补救，而是重写 `Node::release` 直接从原链表摘取元素，从结构上消除"栈上中间链表"反模式。时间线：缺陷随 6.18 引入（eafedbc7c050）；Alice Ryhl 于 2025-11-11 提交修复，合入 6.19-rc1（3e0ae02ba831）并回填 6.18.1（342883126409）；2025-12-16 由内核 CVE 团队分配编号[^3^]（NVD 记录发布时间同为 2025-12-16；GKH 原话"we just assigned our first CVE for some Rust code in the kernel"经 It's FOSS 转录[^101^]，2026-10-27 核对："首个"为内核维护者自述，非独立统计）。影响定性为本地 DoS（CWE-362 竞态），无提权/RCE 证据；Greg Kroah-Hartman 的定性值得原文引述——问题"just causes a crash"，并指出"同日为 C 代码修复分配的另外 159 个内核 CVE"作为对照（经 It's FOSS 转录，二手来源）[^101^]。

#### 6.2.2 教训与系统级实践快照

三条具体教训对 unsafe 审查方法论具有普遍意义。其一，并发不变量是 unsafe 审查的第一优先级：该漏洞不在语言层，而在 unsafe remove 依赖的跨线程独占性假设；进入 unsafe 后，并发不变量即安全边界（Penligent 博客评论，二手）[^102^]。其二，SAFETY 注释的状态枚举必须有全局视图：`Node::release` 引入的栈上链表在 remove 调用点（注释书写处）不可见，跨函数的不变量依赖未被文档化；侵入式链表的 unsafe remove 契约应显式要求"元素不得位于任何可能被并发访问的其他链表"[^3^]。其三，"让不变量在结构上成立"优于"靠纪律维持"：修复消除了反模式本身而非叠加锁。与 C 版 Binder 的 CVE-2019-2215（Bad Binder UAF 提权链）对比，此次崩溃级后果支持 Ryhl 在 LPC 2023 的预判——Rust 将"game over"级漏洞降级为更难利用的逻辑/崩溃级错误[^103^]；但随后 Rust Binder 前向移植遗漏 list_lru 锁 per-cgroup 拆分导致的死锁告警（6.19 周期修复）提示，跨版本 C 侧语义漂移是 unsafe 块之外的另一类持续风险[^104^]。

其他系统级场景呈现同向证据。Android 侧，Rust 代码内存安全漏洞密度约 0.2 个/百万行，对比 C/C++ 历史基线约 1000 个/百万行；Google 实测还表明 unsafe 行并不比 C 行更易错[^2^]。Windows 侧，win32k 的 Rust 代码以 `win32kbase_rs.sys` 出货，DirectWriteCore 达 15.4 万行 Rust；Russinovich 举例同类 bug 在 Rust 内核代码中仅造成确定性蓝屏，在 C++ 中则是潜在提权漏洞（据 The Stack 单一二手来源转述，未见微软官方数据披露，待核实）[^105^]。嵌入式侧，RTIC 基于 Stack Resource Policy 在编译期保证无死锁、无数据竞争，Embassy 以编译期状态机变换实现无动态分配的单栈异步运行时，将"并发不变量封装进类型系统"的思路推至 MCU[^106^]。GPU 驱动成为抽象层的压力测试场：Nova（NVIDIA）与 Tyr（Arm Mali）双线推进，DRM 维护者 Dave Airlie 在峰会上表示该子系统约一年后将对新驱动"要求 Rust、拒绝 C"[^107^]。

## 7. 政策驱动与产业实证

技术与工具供给之外，unsafe 审计需求侧的另一股驱动力来自政策与产业实证。本章先按时间线梳理 2022–2026 年内存安全政策链条，再给出产业侧的关键数据链与基础设施迁移信号——政策文件本身并未直接要求 unsafe 清单化或审计，两者对 unsafe 审计需求的传导多为间接，相关判断标注为推断。

### 7.1 政策时间线 2022–2026

#### 7.1.1 美欧政策链条：从机构倡议到多法域合规信号

2022 年 11 月至 2026 年 9 月，内存安全从机构倡议演进为多法域合规信号，且链条上每一环均可核实至一手出处。美国联邦侧的起点是美国国家安全局（National Security Agency, NSA）2022 年 11 月 10 日发布的网络安全信息单《Software Memory Safety》，首次以联邦政府名义点名六种内存安全语言（memory safe language, MSL）：C#、Go、Java、Ruby、Rust、Swift——**原始名单不含 Python**，此为二手文献中最常见的误记；Python 首次出现在 2023 年 12 月路线图指南的推荐列表中[^108^]。2023 年 12 月 6 日，美国网络安全与基础设施安全局（Cybersecurity and Infrastructure Security Agency, CISA）联合五眼联盟 8 家机构（美 CISA/NSA/FBI、澳 ACSC、加 CCCS、英 NCSC-UK、新 NCSC-NZ/CERT-NZ，**不含德国**）发布《The Case for Memory Safe Roadmaps》，确立"内存安全路线图"（含分阶段日期、新系统采用 MSL 的日期、外部依赖计划等要素）作为政策抓手[^109^]。2024 年 2 月 26 日，白宫国家网络总监办公室（ONCD）发布 19 页技术报告《Back to the Building Blocks》，将 C/C++ 定性为内存不安全的国家安全风险并点名 Rust 为安全语言示例（原始 whitehouse.gov 链接已失效，引用须用 bidenwhitehouse.archives.gov 归档地址）[^110^]。

最具约束力色彩的文件是 CISA 与 FBI 的《Product Security Bad Practices》：2024 年 10 月 16 日草案将"以内存不安全语言开发关键基础设施新产品线"与"2026 年 1 月 1 日前未公布路线图"列为危险不良实践[^111^]；但 2025 年 1 月 17 日定稿**删除了"by January 1, 2026"的硬性日期**，软化为"2025 年底前发布路线图"，并明示文件 non-binding。截至 2026 年 8 月，CISA 未有任何执法、点名或更新版本，其实际传导落在联邦采购与产品责任诉讼的"注意义务"上[^112^]。2025 年 6 月 23 日 NSA/CISA 联合指南《Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development》完成从"为什么"到"怎么做"的转向，并贡献了权威数据点（见 7.2 节）[^7^]。欧洲侧，欧盟《网络弹性法案》（Cyber Resilience Act, CRA，Regulation (EU) 2024/2847）虽技术中立、不指定语言，但其第 14 条报告义务（24 小时预警→72 小时通知→14 天/1 个月终报，罚款上限 1500 万欧元或全球营业额 2.5%）于 **2026 年 9 月 11 日**起适用，以 2026-08 锚点计约 6 周后到期（本文成稿时尚未适用），是当时最迫近的合规事件[^8^][^113^]。另据单一二手来源（corrode.dev，Rust 咨询商，有立场）报道，德国联邦信息安全办公室（BSI）在 NIS-2 安全措施指南中点名 Rust，但一手文档尚未定位，**置信度低，待核实**[^114^]。

| 日期 | 机构 | 文件 | 关键要求/内容 |
|---|---|---|---|
| 2022-11-10 | NSA（美） | Software Memory Safety 信息单 | 建议从 C/C++ 战略转向 MSL；名单 C#/Go/Java/Ruby/Rust/Swift，**无 Python** [^108^] |
| 2023-12-06 | CISA+五眼 8 机构（无德国） | The Case for Memory Safe Roadmaps | 要求软件制造商公布内存安全路线图；MSL 列表首增 Python [^109^] |
| 2024-02-26 | ONCD（美白宫） | Back to the Building Blocks | C/C++ 定性为国家安全风险；点名 Rust [^110^] |
| 2024-10-16 / 2025-01-17 | CISA+FBI（美） | Product Security Bad Practices 草案/定稿 | 定稿删除 2026-01-01 硬性期限，改为"2025 年底前"建议；non-binding [^111^][^112^] |
| 2025-06-24 | NSA+CISA（美） | Memory Safe Languages 联合指南 | 从倡议转向实施方法；披露微软 CVE 内存安全占比 70%→约 50% [^7^] |
| 2026-09-11 | 欧盟 | CRA 第 14 条生效 | 被活跃利用漏洞 24h/72h 双轨报告；覆盖全部存量产品 [^8^] |

**表格解读**：时间线呈现"倡议→定性→标签→方法→法规"五步硬化路径，但硬化程度并不均匀：美国侧全部文件均为指南性质、无强制力，真正带罚则的只有欧盟 CRA。三个常被误记的细节——NSA 原始名单含 Python、Roadmaps 联署含德国、2026-01-01 为已生效硬性期限——经一手 PDF 逐字核对均不成立，引用二手综述（尤其是 2024 年后 AI 生成的聚合文章）时此三处出错率最高。另一个异常值是 2025-01-17 定稿的"软化"：草案的硬日期在征求意见期后被删除且未获任何后续执法，说明美国政策工具箱中"耻辱柱"式标签的实际约束力弱于采购杠杆。

#### 7.1.2 DARPA TRACTOR 与认证体系

国防高级研究计划局（DARPA）的 TRACTOR（TRanslating All C TO Rust）项目以 AI 加程序分析自动将 C 译为地道 Rust，测试评估由 MIT 林肯实验室承担并每六个月发布公开基准；2025 年 7 月，UIUC/UW-Madison/UC Berkeley/爱丁堡大学联合团队的 ForCLift 项目获 500 万美元资助，此为已核实的一手事实[^115^][^116^]。但广泛流传的"2026 年初对 MISRA C 合规代码达 95% 自动化、输出 unsafe 占比 <5%"指标**仅见于 IDST 一家非官方防务媒体，DARPA 与 MIT LL 一手材料中均未检出，置信度低，引用须标注为第三方报道**[^117^]。认证侧，Ferrous Systems 的 Ferrocene 是首个 TÜV SÜD 合格的 Rust 工具链（ISO 26262 ASIL D、IEC 61508 SIL 3——SIL 4 为进行中口径、IEC 62304 Class C），2025 年 12 月认证范围扩展至 core 库子集（IEC 61508 SIL 2）；其催生的 Ferrocene Language Specification（FLS）于 2025 年 3 月捐赠给 Rust 项目，仅部分缓解了"Rust 无语言规范"的合规障碍（FLS 是描述当前实现的 as-implemented 文档，并非规范性语言规范）[^118^][^6^]。

### 7.2 产业实证数据

#### 7.2.1 关键数据链：Android、微软与口径警示

全球引用最广的证据链来自谷歌两篇安全博客：Android 内存安全漏洞占全部漏洞比例 2019 年为 76%（绝对数 223 个），2024 年降至 24%（不足 50 个）[^12^]，2025 年首次跌破 20%[^2^]；策略为"新代码用 Rust/Java，旧代码不重写"。2025 年 11 月博文进一步披露 Rust 漏洞密度 0.2/百万行（MLOC）对 C/C++ 约 1000/MLOC——**口径警示**：0.2 是基于单一未遂事件（CVE-2025-48530，CrabbyAVIF 中 unsafe Rust 线性缓冲区溢出，发布前修复）的保守估计，样本极小，且谷歌自承"其他项目数字会不同"；同文披露 Android Rust 代码约 4% 位于 `unsafe{}` 块，并论证 unsafe 行的实际出错率并不高于 C 行[^2^]。微软数据则需澄清出处："约 70% CVE 源于内存安全"出自 MSRC 2019 年 7 月博文（口径 2006–2018）[^10^]；"降至约 50%"的一手出处是 NSA/CISA 2025 年 6 月指南的图 1（2016–2023 微软 CVE 统计），**并非微软自报**；两口径并存，引用时须注明年份[^7^]；微软 2025-11 SFI 进度报告发布当日（2025-11-10）的 Windows 官方博客（Windows Security 与 Surface 团队署名）仍写"微软每年修复的安全漏洞中 70% 与内存安全有关"，即沿用 2019 年口径[^161^]（2026-10-27 已直读该博客；SFI 报告 PDF 本体未逐页核对，该口径并非新统计）。

#### 7.2.2 基础设施迁移与审计需求传导

操作系统供应链层面，Ubuntu 25.10（2025-10-09）成为首个默认搭载 sudo-rs 与 Rust 版 coreutils（uutils）的主流发行版，Ubuntu 26.04 LTS 延续该路线[^119^]；Debian APT 维护者宣布**不早于 2026 年 5 月**引入硬 Rust 依赖（.deb/.ar/.tar 解析与 Sequoia 签名验证），无 Rust 工具链的架构 ports 须在期限内补齐或退役（截至 2026-08 底稿未见该时点之后的更新，实际落地情况待核实）[^120^]。以下为本报告的推断，非来源原文：CRA 的 24 小时报告时限可能要求组件级可见性，从而间接抬升对 unsafe/FFI 边界清单的需求，但 CRA 技术中立，未见文本要求 unsafe 清单；谷歌的密度数据与 near-miss 解剖（样本有限）提示残余风险可能集中在 unsafe 块与 FFI 边界。据此推断，unsafe 的清单化、审计与形式化验证的需求可能上升，但尚无政策文件直接要求。

## 8. 最佳实践体系

前述各章处理了 unsafe 的语义边界、验证工具与政策背景，本章将其收束为可直接执行的工程体系。总纲可概括为一句话：**unsafe 是证明义务（proof obligation）——`unsafe fn`/`unsafe trait` 创设义务，`unsafe {}`/`unsafe impl` 声明义务已解除，最佳实践就是把义务的范围、内容与验证方式显式化**[^20^]。本章按四层组织：决策框架、lint 强制的工程规范、不变量编码、审计与复盘，主要条目可在 Rustonomicon、std 官方 API 文档、ANSSI 指南、Clippy 文档与 RustSec 公告库中核实到一手出处，个别条目引用个人博客等二手来源（已标注）。

### 8.1 决策与边界

#### 8.1.1 何时使用 unsafe：三场景清单与默认禁止

法国国家网络安全局（ANSSI）的《Secure Rust Guidelines》Rule LANG-UNSAFE 给出了目前最权威的准入清单：安全开发中应避免 unsafe 块，仅三类场景允许且必须附正当理由——(a) FFI 调用 C 函数，应定义安全包装器；(b) 嵌入式固定内存地址（如内存映射寄存器）访问，应提供抽象以最小化 unsafe 访问点；(c) 函数行为不可避免地依赖参数安全性时标记 `unsafe fn`；除此之外，crate 根部必须写 `#![forbid(unsafe_code)]`，使任何 unsafe 直接成为编译错误[^121^]。`forbid` 与 `deny` 的差别在于前者不可被内层 `#[allow]` 覆盖，因而适合作为"本 crate 100% safe"的可宣传承诺——async-broadcast 等 crate 已把它用作供应链安全信号[^122^]。但需明确：`forbid`/`deny` 只约束当前 crate，管不到依赖树，依赖中的 unsafe 只能由 cargo-geiger 与审计流程覆盖（见 8.3.2）。

与准入清单互补的是两条心智模型。其一，unsafe 不是性能开关，更不是借用检查器的逃生舱；安全性的根本属性是 soundness（健全性，即任何安全调用方代码都无法经你的安全 API 触发未定义行为），而"和借用检查器搏斗"是公认的反模式[^20^]。其二，soundness 是非局部的：把 `get_unchecked` 前置判断从 `<` 误改为 `<=`——一处纯安全代码改动——即可令整个函数 unsound，因此"限制 unsafe 作用域的唯一防弹方式是模块边界加私有性"[^123^][^124^]。实操推论有三：承载不变量的字段一律私有；类型不变量写进 struct 文档；审计 unsafe 时必须连同模块内的安全代码一起审。

#### 8.1.2 SAFETY 注释规范与 clippy lint 启用组合

注释规范的工程化核心是"一块一操作"：每个 unsafe 块只包含一个 unsafe 操作，使每处操作都能配一条针对性的 `// SAFETY:` 注释；把整个函数体包进一个大 unsafe 块会让审计者无法定位哪条前置条件服务于哪个操作，edition 2024 默认开启的 `unsafe_op_in_unsafe_fn` 正是针对此反模式（[^125^] 为个人博客，二手）[^125^][^126^]。一条合格的 SAFETY 注释含四要素：该操作的前置条件、前置条件为何在此成立（引用不变量或上游检查）、涉及的类型/模块不变量、（若为 `unsafe fn` 的 `# Safety` 文档段）调用方义务[^125^]。Jack Wrenn（个人博客，二手[^127^]）将整套规范形式化为 safety hygiene 三规则：创设义务时关键字加解释（`unsafe fn` 配 `# Safety` 段）、解除义务时关键字加解释（`unsafe {}` 配 `// SAFETY:` 注释）、无义务时两者都不用——不要把 `unsafe fn` 当作"内部实现很可怕"的标记[^127^]。2026 年 1 月的 Pre-RFC《Rust Safety Standard》（复旦大学徐辉组发起）进一步提出两条强制规则：所有 `unsafe fn` 必须文档化安全需求，且**安全需求必须外部可验证、不得依赖函数内部实现**；unsafe trait 实现处不得加码安全需求。截至 2026 年 8 月该提案仍处 Pre-RFC 讨论阶段，未进入正式 RFC[^99^]。

```rust
/// # Safety
/// `ptr` 必须非空、按 `T` 对齐、指向已初始化的 `T`，其有效期覆盖 `'a`，
/// 且在 `'a` 内不存在对该内存的并发可变别名。
unsafe fn first_unchecked<'a, T>(ptr: *const T) -> &'a T {
    // SAFETY: `# Safety` 契约要求 ptr 非空、对齐、指向已初始化的 T、
    // 有效期覆盖 'a 且无并发可变别名，调用方已承担这些义务。
    unsafe { &*ptr }
}
```

下表汇总与 unsafe 直接相关的 lint 及其启用现状，构成可强制执行的闭环。

| lint | 归属 | 强制内容 | 启用现状 |
|---|---|---|---|
| `undocumented_unsafe_blocks` | clippy（Rust 1.58+） | 每个 unsafe 块必须配 SAFETY 注释 | Rust for Linux 2024-09 全树启用，2025-03 回移植 6.12 stable [^126^] |
| `unnecessary_safety_comment` | clippy | 无 unsafe 操作处禁止挂 SAFETY 注释 | 内核与前者同步启用 [^126^] |
| `missing_safety_doc` | clippy | `unsafe fn`/trait 必须有 `# Safety` 文档段 | 默认 warn [^128^] |
| `unsafe_op_in_unsafe_fn` | rustc | unsafe fn 体内仍须显式 unsafe 块 | edition 2024 默认 warn [^128^] |
| `unused_unsafe` | rustc | 冗余 unsafe 块/impl | 默认 warn [^128^] |
| transmute 专项族（`transmute_undefined_repr`、`transmute_int_to_bool`、`transmutes_expressible_as_ptr_casts` 等 9 项） | clippy | 布局、有效性、指针语义陷阱 | 默认 warn（correctness/suspicious 组） [^128^] |

**表格解读**：这组 lint 的设计呈现出明显的"成对"结构——前三行分别管"有 unsafe 必须有注释""无 unsafe 禁止有注释""有义务必须有文档"，合起来恰好是 safety hygiene 三规则的机械化，说明规范并非社区习俗而是工具链的设计意图。启用现状上的异常值是 `undocumented_unsafe_blocks`：它在 2024 年之前几乎只有嵌入式项目（heapless 等）以 issue 级规范人工执行，Rust for Linux 的全树启用及向 6.12 stable 分支的回移植（一个文档类 lint 进入 stable 分支本身罕见）把它从可选项变成大型项目的行业基准。transmute 专项族则以 9 个细粒度 lint 覆盖 8.2.2 节的四重陷阱，是把"Nomicon 警告"编译期化的最完整样本；但 `missing_safety_doc` 等 lint 升级为 hard error 目前无官方时间表，依赖各项目自行 `#![deny]`。

### 8.2 不变量编码与易错点

#### 8.2.1 用类型系统编码不变量

第一条规则是私有字段防字面量构造：公开字段允许 `Struct { field: ... }` 字面量构造，可绕过构造函数的安全契约。真实反例来自标准库自身——`Pin<P>` 因公开单字段允许字面量构造，可绕过 `Pin::new_unchecked` 的契约，被正式认定为 unsound（rust-lang/rust#139013），且因 `pin!` 宏依赖该字段暂时无法修复，只能以 `#[doc(hidden)]` 加 `unsafe_pin_internals` feature 缓解[^129^][^130^]。指针字段应使用 `NonNull<T>`（官方定义："`*mut T` 但非空且协变"，与 `Box`/`Vec` 同款并享 niche 优化）；若类型可经 `NonNull` 暴露对 `T` 的可变访问，须加 `PhantomData<Cell<T>>` 或 `PhantomData<&'a mut T>` 制造不变性，官方文档的原话是"如果你不确定，就用 `*mut T`"[^131^]。

`PhantomData` 模式表沿方差、auto trait、drop check 三轴控制类型的隐式性质，但必须按 RFC 1238（非参数化 dropck）后的规则理解：**类型只要有 `impl<T> Drop`，编译器即视其 owns T，再为 drop check 添加 `_owns_T: PhantomData<T>` 字段是多余的**——旧教程中"容器必须加 `PhantomData<T>` 否则 dropck 漏检"的说法已过时；该字段仍影响方差与 auto trait，而 std 的 `Vec` 保留它仅因为其 `Drop` 实现使用了 std 专属的不稳定承诺 `unsafe impl<#[may_dangle] T> Drop`（"我发誓 drop 时不使用 T"），用户代码不可用该属性[^132^][^133^]。未初始化内存的正确流程是 `MaybeUninit::uninit()` → `as_mut_ptr()`/`&raw mut` 逐字段 `write` → 全部就绪后 `assume_init()`；三个高频误区均有官方文档背书：(1) 用 `assume_init_mut()` 制造指向未初始化内存的引用——官方三个 Incorrect 示例全部定性为即 UB；(2) `MaybeUninit::zeroed().assume_init()` 用于引用、`NonNull`、`NonZeroU32`、`Box` 或判别值不含 0 的 enum——全零不是这些类型的合法位模式即 UB（注意 `bool` 的全零即 `false`，是合法的）；(3) 使用已废弃的 `mem::uninitialized()`——官方定性"对几乎所有类型（含整数及其数组）调用此函数都是立即未定义行为，即使结果未被使用"[^134^][^135^]。pin projection（从 `Pin<&mut Self>` 投影到字段）应手写改为宏生成：手写 projection 与 `Drop::drop(&mut self)` 的签名存在结构性冲突（值被 pin 过后仍可取得 `&mut Self`），pin-project 宏禁止手写 `Drop`、强制改实现 `PinnedDrop`（签名为 `drop(self: Pin<&mut Self>)`）；学术工具 PinChecker 已在 crates.io 上发现真实 pin soundness bug，手写 projection 是重灾区[^136^]。

#### 8.2.2 panic safety、Send/Sync 决策树与 transmute 陷阱

panic safety 的最低义务是：unsafe 代码中 panic 不得违反内存安全（safe 代码才追求 panic 后行为仍正确的更强级别）。凡在临时 unsound 状态期间调用可 panic 的用户代码（`clone`、比较器）的 unsafe 代码，要么只运行不可 panic 代码，要么用 RAII guard 兜底[^137^]。两条落地模式：`set_len` 永远只陈述"已经成立的初始化事实"——`Vec::push_all` 反例中先 `set_len(len+n)` 再克隆，克隆 panic 即读到未初始化内存，修法是循环内逐步 `set_len` 或循环结束后再设置；以及 std `BinaryHeap::sift_up` 的 Hole 模式——把算法状态收进独立结构体，其 `Drop` 无论是否 panic 都把取出的元素写回"洞"位，宁可观察到逻辑不一致也绝不 double-drop[^137^]。与之同源的铁律是**泄漏是安全的**：`mem::forget` 是安全函数，unsafe 代码不得依赖析构函数一定运行；`vec::Drain` 在构造时先 `set_len(start)`，被 forget 时只是多泄漏几个元素（leak amplification）而非 use-after-free——设计 guard/代理类 API 时先问"用户 forget 掉它会怎样"，答案必须是"最多泄漏，绝不 UB"[^138^]。

手写 `unsafe impl Send/Sync` 已有成熟决策树：(1) 优先让类型由已具正确 auto trait 的字段自动派生——裸指针 `!Send`/`!Sync` 是有意的 lint 式设计，逼你封装；(2) `Send` 判据：值能跨线程移动且能在他线程 drop（含跨线程 `free` 合法性）；(3) `Sync` 判据：无法通过 `&T` 非同步地得到可变访问，若存在公开 `Deref<Target = T>` 路径则 `Container<T>: Sync` 需要 `T: Sync`；(4) 锁能把值跨线程"运送"，故 `unsafe impl<T> Sync for SpinLock<T> where T: Send`（Mara Bos 经典边界）；(5) guard 类型常需刻意 `!Send`（std `MutexGuard`：底层锁要求同线程解锁）；(6) 可写 `where Box<T>: Send` 直接继承 std 语义[^139^][^140^]。RustSec 数据库中 Send/Sync 边界缺失或过宽是最高频的 unsound 类别（aovec、im、concread、futures-util 等一串公告），故该决策树应按条目逐一核对而非凭直觉[^85^]。transmute 使用前须核对四重陷阱：两侧 size 相等（泛型下编译器检查易漏）、默认 `repr(Rust)` 布局无保证（跨类型 transmute 一般要求 `repr(C)`/`repr(transparent)`）、目标类型每个位模式都须合法、能写指针 cast 就别 transmute——每一点都对应上表中 clippy 的专项 lint，工程上等价于"把 transmute 族 lint 设为 deny 并逐条处置"[^128^]。

### 8.3 反面案例与审计清单

#### 8.3.1 经典事故复盘

反面案例的价值在于它们几乎都是"审计加测试仍然漏网"的样本。smallvec 一个 crate 集齐五张 RustSec 公告，覆盖几乎全部经典事故类型，维护者 mbrubeck 公开坦承"soundness bugs have slipped through a few times"，并在 2021 年的修复中"简化实现以减少 unsafe 代码，便于验证正确性"[^141^]。`thread::scoped` 之死（史称 leakpocalypse）则是设计层面的教训：1.0 前的 `thread::scoped` 靠 `JoinGuard` 析构函数隐式 join 保证安全，但 `mem::forget(guard)` 是安全操作，可令父线程栈帧弹出时子线程仍持有引用，该 API 被整体移除；正确解法是闭包式作用域——crossbeam 验证多年后经 RFC 3151 进入 std（1.63 稳定），`thread::scope(|s| s.spawn(...))` 用函数作用域而非析构保证 join 必然发生，由此确立"生命周期保证必须由控制流必然经过的点承担，不能由值被析构承担"的设计准则[^142^][^143^]。`mem::uninitialized()` 的官方定性（见 8.2.1）则表明：连标准库都曾提供"几乎无法正确使用"的 API，对存量代码的排查应作为审计固定项[^135^]。

| 案例 | 编号/年份 | 失效机制 | 对应正面实践 |
|---|---|---|---|
| smallvec `insert_many` 回滚缺陷 | RUSTSEC-2018-0003 | unwinding 时 double free | panic safety 最小义务；Hole 模式 [^141^] |
| smallvec 用 `mem::uninitialized` 构造泛型 T | RUSTSEC-2018-0018 / CVE-2018-25023 | T 为引用类型时即 UB | MaybeUninit 三误区；0.6.13 修复 [^141^] |
| smallvec `grow()` 容量边界 | RUSTSEC-2019-0009 / CVE-2019-15551（CVSS 9.8） | 已 spill 时按当前容量调用即 double-free + UAF | 边界条件审计 [^141^] |
| smallvec `insert_many` 缓冲区过小 | RUSTSEC-2021-0003 | 信任 iterator `size_hint` 下界，堆溢出 | 防御外部契约；减少 unsafe 表面积 [^141^] |
| `std::thread::scoped` 整体移除 | leakpocalypse（2015）；RFC 3151（1.63 稳定） | 安全依赖析构函数运行，`mem::forget` 可破 | 泄漏是安全的；控制流承担生命周期保证 [^142^] |
| `mem::uninitialized()` 废弃 | Rust 1.39（2019） | 对几乎所有类型调用即 UB，即使未使用 | MaybeUninit 替代 [^135^] |
| std `Pin<P>` 字面量构造 | rust-lang/rust#139013（2025，未修复） | 公开字段绕过 `Pin::new_unchecked` 契约 | 私有字段防字面量构造 [^129^] |

**表格解读**：七起事故可归入五个失效族——panic 时序族（第一行）、未初始化内存族（第二、六行）、信任外部契约族（第四行）、边界条件族（第三行 `grow()` 容量边界，属算术/状态边界错误，不属信任外部契约）、封装边界族（第五、七行）；除边界条件族只对应"边界条件审计"这一笼统建议外，其余各族在本章 8.2 节都有对应的正面规则，说明事故模式较为有限、可枚举，code review 清单可以按族核对而非泛读。值得注意的异常值是 RUSTSEC-2019-0009 的 CVSS 9.8：smallvec 是被广泛依赖的基础 crate（并非小众），其 unsafe 缺陷即可达到与网络服务 RCE 同级的评分，unsafe 审计的优先级应按暴露面而非 crate 体量排序。另一观察是时间跨度：smallvec 五条公告（表中列出 4 条，第五条 RUSTSEC-2019-0012 见[^141^]）横跨 2018–2021 年且均发生在维护多年的项目上，而 `Pin` 事件（2025 年认定）说明连标准库仍在偿还封装债务——"老牌即安全"的假设在 unsafe 领域不成立，这与第 7 章所述（推断性的）unsafe 审计常态化需求方向一致。

除上述个案外，RustSec 公告库的高频聚类还包括：Send/Sync 边界缺失或过宽（aovec、im、concread、reffers、lock_api）、panic 时 double-drop（glsl-layout RUSTSEC-2021-0005）、安全 API 暴露内部裸指针（cache RUSTSEC-2021-0006）、依赖析构保安全（http crate `HeaderMap::Drain`，RUSTSEC-2019-0034）、生命周期幻影（futures-task waker 非 `'static` 导致 UAF，RUSTSEC-2020-0060）——每一类都可直接映射为本章一条正面规则，适合作为 code review 的反面训练集[^85^]。

#### 8.3.2 含 unsafe 依赖的审计清单

审计供给的现状并不乐观：IEEE S&P 2024 对 160 名用过 unsafe 的开发者（问卷调查）的调查显示，**88% 的受访者审计其依赖项 unsafe 使用的频率不足一半**，仅 51% 用过自动化审计工具（cargo-audit 63%、cargo-geiger 22%、cargo-vet 仅 7%），仅 23% 始终确信自己的 unsafe 封装是 sound 的[^9^]。方法论侧的突破来自两项 2026 年工作。其一是 Cargo Scan（ESOP 2026）：用副作用（effect）分析跨 crate 追踪潜在危险操作，审计 hyper 及其全部 30 个依赖（约 16 万行）时人工审阅面压至**中位数 0.2% 代码行**，top-10K crates 中 3,434 个可自动判为"pure"；该研究同时指出 `#![forbid(unsafe_code)]` 的信任幻觉——axum 宣称 100% safe，但其依赖的 hyper 传递树中确有 unsafe[^89^]。其二是 safety-tag 方法论（arXiv:2504.21312）：把 SAFETY 注释翻译为 21 个机器可检查的安全标签（layout、pointer validity、content、alias、contextual 五类，覆盖 96.1% 的公开 unsafe API），审计任务即沿调用链检查每条义务是被内部检查消解还是被正确标注移交调用方；对标准库的实证审计发现 27 个 API 的 61 处文档缺陷，修复已全部被官方合并[^57^]。

综合 ANSSI checklist 与 Rust Secure Code WG 供应链指南，含 unsafe 依赖的审计可按七步 SOP 执行：①锁定版本，审 `Cargo.lock` diff，并以 crates.io 发布 tarball（而非仓库源码）为审阅对象——两者可能分叉，且**仅在 IDE 中打开不可信 crate 即可经 proc-macro 执行任意代码**，应使用纯文本编辑器或受限模式[^144^][^145^]；②cargo-audit/cargo-deny 过已知公告，`--deny unsound` 把信息级 unsound 公告升级为 CI 失败[^145^]；③用 cargo-geiger 或 Cargo Scan 圈定 unsafe 分布作为审计分诊地图——geiger 输出是统计输入而非风险评分[^84^]；④逐 unsafe 块核对 SAFETY 注释四要素，可按 21 标签法分类检查义务的消解或移交[^57^]；⑤build.rs、proc-macro、FFI 边界按可执行代码最高信任级审；⑥以 Miri（含 `cargo careful` 中间档）、loom、fuzz 做动态兜底[^49^][^46^]；⑦审计结论固化为 cargo-vet 记录或内部豁免清单，使下次依赖升级只审增量。这套流程把"审 unsafe 依赖"从一次性的通读劳动，转变为可增量、可委托、可机器辅助的常态工序。
## 9. 学术谱系、开放问题与趋势展望

前八章以语义机制、工具工程与政策需求为主线；本章回到学术谱系与前瞻判断：soundness 形式化证明如何从 RustBelt 演进到 VerusBelt、当前各类"已验证"声明的语义天花板在哪里，以及 2026 年最值得跟踪的制度化与 AI 辅助趋势，最后给出证据使用指南。

### 9.1 soundness 证明谱系

#### 9.1.1 从 RustBelt 到 VerusBelt：范式确立与 TCB 分化

unsafe Rust 形式化的学术地基是 RustBelt（POPL 2018）：用 Iris 高阶并发分离逻辑在 Coq 中把 Rust 类型解释为"安全契约"，经 fundamental theorem 与 adequacy 定理得出**条件式**结论——只要 unsafe 仅出现在已证明满足接口契约的库中，程序即无 undefined behavior（UB）。论文机器检查了 Arc、Rc、Cell、RefCell、Mutex、RwLock 等库的 $\lambda$Rust 移植版，并顺带修复了标准库真实 soundness 缺陷（`MutexGuard<Cell<i32>>` 不应为 `Sync`）[^146^]。引用须保留两点限定：验证对象是手工移植版而非 std 原码；traits、panic、自动析构明确未建模[^146^]。

谱系随后沿四条支线推进。RBr1x（POPL 2020）基于 ORC11/iRC11 弱内存模型重验并发库，发现 `Arc::get_mut` 一处 relaxed 读不足的数据竞争，修复已并入 rustc；顺序一致（SC）原子的分离逻辑至今仍是 2020 年挂起的开放问题[^147^]。RustHornBelt（PLDI 2022 杰出论文，按交叉验证裁定更正"POPL 2021"口径）以参数化预言（parametric prophecies）把可证性质提升到一阶功能正确性，成为 Creusot 的元理论[^148^]。RefinedRust（PLDI 2024）直接验证真实 Rust（含 unsafe），全部证明由 Coq 内核检查，但自认不覆盖 niche 布局、指针-整数转换、别名模型与并发——"foundational"不等于"全覆盖"[^149^]。VerusBelt（PLDI 2026 杰出论文兼杰出 artifact）首次为 Verus 子集给出机器检查的语义 soundness 证明，覆盖完整生命周期、并发与可变借用，但明确不验证 Verus 实现、验证条件翻译与 Z3[^65^]。找 bug 一端，RUXt（ECOOP 2025）把不正确性分离逻辑引入 Rust，其 Rocq 机械化的 inadequacy 定理保证零误报[^79^]。

**表 9-1 soundness 证明工作谱系与可信计算基（TCB）对比**

| 工作（会议/年份） | 证明载体 | TCB 核心 | 明确在 TCB 外／未覆盖 |
|---|---|---|---|
| RustBelt（POPL'18）| Coq 全机器检查 [^146^] | Coq 内核＋$\lambda$Rust 语义＋Iris 公理化 | traits、panic、relaxed 内存、自动析构；真实 Rust ≠ $\lambda$Rust |
| RBr1x（POPL'20）| Coq [^147^] | 同上＋ORC11/iRC11 模型 | SC 原子（开放问题） |
| RustHornBelt（PLDI'22）| Coq [^148^] | 同 RustBelt＋参数化预言模型 | 手工移植 $\lambda$Rust；自身非工具 |
| RefinedRust（PLDI'24）| Coq 内核检查生成证明 [^149^] | Coq 内核＋嵌入语义＋未验证的前端翻译 | niche 布局、ptr-int cast、别名模型、并发 |
| VerusBelt（PLDI'26）| Rocq（Iris）[^65^] | Rocq 内核＋$\lambda$Verus 语义＋LeLiLo | Verus 实现、VC 翻译、Z3、被公理化的 std 库 |
| RUXt（ECOOP'25）| Rocq 定理＋OCaml 原型 [^79^] | Rocq 内核＋RUXtBelt 语义 | SB/TB 别名 UB（漏报）；仅小模型语言 |
| Gillian-Rust（PLDI'25）| 无机械化元理论 [^150^] | Gillian 引擎＋编译器＋两处未证明的元理论简化 | later modality、预言防环义务、SB/TB |
| Kani（论文 2026）| CBMC 有界模型检查 [^52^] | CBMC＋MIR→Goto-C 翻译＋布局具体化 | 别名、数据竞争、provenance UB、线程、终止性、FFI |

表 9-1 揭示该谱系最稳定的张力轴是"TCB 大小 vs 自动化程度"。五个 foundational 工作的信任基收敛于"证明助手内核＋理想化语义定义"，剩余信任点不在逻辑而在模型保真度——$\lambda$Rust 与真实 Rust 的契合无法用内核检查消除；非 foundational 工具把整个引擎或 SMT 求解器计入 TCB，换取数量级速度（Gillian-Rust 的 EvenInt 案例 0.04 秒对 RefinedRust 的 4 分 36 秒，对比出自 Gillian-Rust 一方论文，宜作量级参考）[^150^]。任何"已机器证明"声明都应绑定其 TCB 清单与未覆盖语义面。

#### 9.1.2 开放问题清单与工具间 soundness 相互指摘

工程性开放问题已由 AWS 标准库验证论文量化。泛型是最大缺口：9,635 个函数（占被跳过函数的 56%）因编译期单态化被自动 harness 生成跳过；intrinsics 方面 71 个不支持、813 个未建模（721 个为 LLVM SIMD），直接导致 4,778 个 harness 失败[^56^]。并发与弱内存是最深的洞：挑战 7（原子类型）与挑战 27（Arc）均要求证明无数据竞争，截至 2026-03 零被接受解——relaxed 至 SC 排序下的跨线程不变式需要形式化内存模型才能表达[^56^][^4^]。第四类是 provenance 与历史依赖规约：`MaybeUninit` 初始化历史、`Rc::from_raw` 要求指针来自 `into_raw` 等属性无法用普通前置条件表达[^4^]。

概念层面还有更深的裂缝：Belt 谱系的语义类型学从不建模任何别名模型，其证明结果"可能与某些编译器优化不兼容"。Tree Borrows（PLDI 2025 杰出论文）在 3 万 crate 评测中把别名违规从 Stacked Borrows 的 6,568 例降至 3,023 例（减 53.97%，仅 31 例反向回归），但"well-typed 安全程序必通过 TB"仅经 Miri 大量测试而未形式化证明，且不存在在 TB 下证明程序正确的程序逻辑框架[^31^]；将 TB 与分离逻辑结合是公开的 future work（ETH 2025 年硕士论文已起步）[^151^]。两个别名模型在接受的程序与允许的优化上互不一致、均非 canonical，任何"无别名 UB"声明都必须注明以哪个模型为准。

工具间的相互指摘为同一结论提供旁证。RUXt 论文正式指摘 Kani"对多个 Rust 特性 unsound——如未初始化内存检测与别名规则违规"，兼有误报与漏报[^79^]；Kani 官方 2026 年论文自认前提清单：顺序执行、不建模 Stacked/Tree Borrows（称其为"unsafe Rust 中主要的 UB 类别"）、FFI、用户保证终止[^52^]。双方口径实质一致：当前"验证通过"的语义天花板是"无 panic／无越界／契约成立"而非"无 UB"，引用时必须附保证清单。

### 9.2 趋势展望

#### 9.2.1 标准库验证挑战赛的制度化与治理风险

verify-rust-std（2024-11-20 由 AWS 与 Rust Foundation 联合启动，背景为 std 约 3.5 万函数、约 7,500 个 unsafe、近三年 57 个 soundness issue）[^152^] 正从一次性众包沉淀为常态基础设施。制度化的硬证据有三：工具白名单远不足 17 个，且随时间变动：2026-08-02 抓取口径为 4 个批准（Kani、ESBMC/GOTO-Transcoder、VeriFast、Flux）；2026-10-27 复核 model-checking/verify-rust-std 当前清单，README 列 5 个（Flux、ESBMC/GOTO Transcoder、Kani、KMIR、VeriFast），doc/src/tools.md 的 Approved tools 列 6 个（ESBMC、Flux、Kani、KMIR、RAPx、VeriFast），二者本身也不一致；tools.md 当前无"审批中"分节，Verus、Creusot、KRust 均未出现在任一清单。"审批中"一说仅见 2026-03 论文口径（Verus、Creusot、KRust、RAPx；2025-10 论文口径为 RAPx、Creusot、KMIR），其后 RAPx、KMIR 已入批准清单，Verus/Creusot 的现状未能在仓库页面查实，"17 个白名单"口径经官方 tools.md 核实不成立[^153^][^56^][^4^]；CI 工程可行——每次代码变更全量运行 16,748 个 harness，3.97× 加速后单次约 69 分钟[^52^]；函数契约已被接受为实验性语言特性，std 契约插桩正式立项，验证从外部运动进入语言路线图[^56^]。

可持续性则有三个未决变量。**治理单点**：PR 须至少两名委员会成员批准方可合并，委员会"主要由 Amazon 员工组成"，24/27 个挑战由 AWS 提出，瓶颈在评审带宽[^154^][^4^]。**证明腐化**：上游每六周一个 release，人工契约产出 2025-10 后进入平台期，契约上游化仍是官方自列的开放挑战[^56^]。**CI 绿灯盲区**：挑战赛（人工 725 个 harness 为约 16 个月的手工积累；16,748 个是 Autoharness 自动生成总量，二者口径不同、不可混为"16 个月 16,748 个"，见 4.2.2）迄今发现**零个**此前未知的内存安全漏洞（论文未按 harness 口径拆分），产出集中在规约缺陷（错误 SAFETY 注释、缺失标注、文档错误）；Lessons 论文作者自认可能有确认偏差，建议并行运行 Miri 等动态分析[^4^]。CI 绿灯的正确读法是"规约卫生＋回归保护"，而非"无 bug"。

### 9.2.2 AI 辅助验证五线与"证明义务形式化"演进线

背景是 Autoharness（Kani 内置的自动 harness 生成，非 LLM）：它一次生成 16,748 个 harness（其中 11,970 个通过），而人工 725 个是约 16 个月的手工积累，二者为不同口径、不宜直接比作"跃升"[^56^]。在此之上，2026 年 AI 辅助验证呈五条平行线，评测基准各异（并非都取自挑战赛资产）：KaPilot 从文档抽取安全需求生成 Kani 规约，在以挑战赛人工契约为 ground truth 的 GoldSet 上达 88.9% 成功率、57.4% 等价或更强[^155^]；KVerus 以 RAG＋错误驱动自修复生成 Verus 证明，单文件成功率 80.2%（AutoVerus 为 56.9%）、仓库级 51.0% 对 4.5%，23 个未验证函数的证明获上游接受[^156^]；Aria 用通用 code agent 重做 RustBelt 的 217 个引理且零失败（评测对象是 RustBelt 引理，非挑战赛资产）[^157^]；Rust→Lean 管道（Charon/Aeneas 提取＋AI 证明器闭义务）计划对每个新 `sorry` 自动跑 CI[^158^]；HarnessLLM 在 Autoharness 成功率仅 41% 的复杂类型场景达 100%[^159^]。五线共享同一治理模式：**证明助手内核复查是接纳 AI 输出的统一信任边界**——AI 降低证明成本，内核裁决证明效力（各成功率均为论文自述，生产泛化待独立复核）。

与之并行的是一条更慢的"证明义务形式化"演进线：Reference 已采纳的 define/discharge 框架[^13^]；学术工作把 SAFETY 注释提炼为 21 个机器可读 safety-tags 标签，其对标准库的审计所发现的 27 个 API、61 处文档缺陷已修复并入 std（标签体系本身是否进入 std 未见证据）[^57^]；函数契约继而成为实验性语言特性[^56^]。unsafe 边界上的安全论证正从"给人看的散文"演变为"给工具检查的规约"——今天按机器可读格式书写安全论证的代码，将是明天工具红利的第一批受益者。

#### 9.2.3 证据使用指南：可放心引用与需打折的声明

可放心引用（同行评议＋机器检查）：RustBelt 的语义 soundness 范式与"unsafe 库＝可验证安全扩展"框架（保留"$\lambda$Rust 移植版"限定）[^146^]；学术证明产出真实 std 修复的两个硬核案例——`MutexGuard` Sync 缺陷与 `Arc::get_mut` 数据竞争[^146^][^147^]；RustHornBelt 作为 Creusot 元理论、VerusBelt 的精确覆盖范围、RUXt 的零误报定理[^148^][^65^][^79^]。

需打折或附前提的宣传："Rust 标准库已被形式化验证"——实际为 989 个函数带契约、11,970 个 harness 通过，不含量最大的别名 UB、数据竞争与部分 provenance UB，"通过当前全部检查的函数在更完整模型下仍可能有 UB"[^56^]；"RustBelt 证明了 Rust 安全"——定理是条件式的，$\lambda$Rust ≠ 真实 Rust[^146^]；"Verus 验证结果被内核背书"——VerusBelt 明确不覆盖实现、VC 翻译与 Z3[^65^]；"最大规模验证运动发现了多少 bug"——零个新内存安全漏洞，价值在规约卫生，且"最大规模"为作者自述，宜保留限定语[^56^]。

## 10. 结论

### 10.1 核心判断

#### 10.1.1 unsafe 是 Rust 安全体系的基石而非漏洞

现有有限证据与下述判断一致（样本很小，见 7.2.1：Android 0.2 个/百万行仅基于单一 near-miss，内核仅有一个公开分配的 CVE，均不足以定论）：Rust 倾向于把内存安全风险压缩进一个较小、可枚举、可审计的表面。Linux 内核 Rust 驱动的 unsafe 代码占比为 0.76%–3.4%[^1^]；Android 侧 Rust 代码漏洞密度估计为 0.2 个/百万行，比 C/C++ 低约三个数量级，Google 称 unsafe 行并不比 C 行更易错[^2^]。需要澄清的是，Miri 的 7.8%（4,595/59,136）是有测试库中的 UB 检出率，分母并非 unsafe 代码，不能作为 unsafe 占比小的证据，反而提示生态中 UB 并不罕见[^5^]。截至锚点首个公开分配 CVE 的内核 Rust 代码缺陷（CVE-2025-68260）恰恰发生在 SAFETY 注释的论证前提被并发场景打破之处，而非 unsafe 机制的滥用[^3^]。这意味着 unsafe 不是 Rust 安全体系的裂缝，而是其承重结构：《Rust Reference》17.1 章已将其统一表述为"定义或消解证明义务"的框架[^13^]。相应地，评估一个 Rust 项目安全性的范式正从"计数 unsafe"转向"审计边界不变量"——unsafe 边界上的不变量是否被文档化、被测试、被机器检查，成为比 unsafe 行数更有预测力的指标。

#### 10.1.2 三类读者的行动建议

**库作者：抄内核与标准库的作业。** 最严格的 unsafe 工程纪律（不变量文档化、类型编码、最小 unsafe 块）已在"不能出错"的场景淬炼成型：内核全树强制 SAFETY 注释[^126^]，safety-tags 方法论（独立学术工作，非挑战赛产出）审计标准库所发现的 27 个 API、61 处文档缺陷已修复并入 std[^57^]。普通库作者无需自创流程，直接采用这套注释规范即可；验证侧应将 Miri（别名与数据竞争 UB）与 Kani（功能与安全属性）视为互补——Kani 官方自认不建模 Stacked/Tree Borrows 与并发，单独使用任一者都存在系统性盲区[^52^]。

**企业：把分层工具链与供应链审计接入 CI。** 政策压力在上升（但无文件直接要求 unsafe 审计），而供给侧明显滞后：160 名问卷调查受访者中 88% 对所用依赖的 unsafe 审计不足半次，cargo-vet 使用率仅约 7%[^9^]；可行的规模化路径是机构间审计互导（现有 9 家组织共享审计集）而非个人信任网络[^87^]。企业级基线应是"动态检测（Miri/cargo-careful）＋静态验证（Kani 等）＋依赖审计（cargo-vet/cargo-audit）"三层并行，且引用任何"已验证"声明时要求其附保证清单。

**研究者：跟踪规范化进程作为最大中期变量。** Tree Borrows 成为 Miri 默认尚无正式 FCP[^33^]，rust-lang/rust #132898 编译器误编译问题仍 open[^35^]；T-opsem 团队 2026 年目标产出"Normative Documentation for Sound unsafe Rust"，一旦落地，今天大量依赖未文档化上游行为的 unsafe 写法将被重新裁决[^39^]。在此之前，"在两个别名模型下都成立"是最稳妥的保守准则。

unsafe 边界上的安全论证正沿"SAFETY 注释 → lint 强制 → 机器可读标签 → 契约语言特性"的轨迹从给人看的散文演变为给工具检查的规约[^13^][^57^]；T-opsem 的规范化文档与进入 LLVM 的 BorrowSanitizer[^39^][^40^] 有望使"证明义务形式化"从愿景变为基础设施。

# 参考文献


编号按各章正文首次引用顺序（sec01→sec10）从 1 连续分配（事后修订使个别编号的首次出现位置略有前移，编号本身未变）；跨章节相同 URL 来源已合并为同一编号。

[^1^]: Understanding the Security Impact of Rust in the Linux Kernel（ACSAC 2024，Table 4 unsafe 密度） — Mars Research / University of Utah，2024-12. https://mars-research.github.io/doc/2024-acsac-rfl.pdf
[^2^]: Rust in Android: move fast and fix things（Rust 0.2/MLOC vs C/C++ ~1000/MLOC；2025 年内存安全漏洞占比 <20%；unsafe 行不比 C 行更易错） — Jeff Vander Stoep / Google Security Blog，2025-11-13. https://security.googleblog.com/2025/11/rust-in-android-move-fast-fix-things.html
[^3^]: rust_binder: fix list remove in Node::release（修复 commit 全文，含被攻破的 SAFETY 注释与根因分析） — kernel.org stable（Alice Ryhl），2025-11-11. https://git.kernel.org/stable/c/3428831264096d32f830a7fcfc7885dd263e511a ; https://nvd.nist.gov/vuln/detail/CVE-2025-68260
[^4^]: verify-rust-std Issue #108 "Tool proposal: GOTO Transcoder (ESBMC)" + Lessons Learned 论文（k-induction/增量 SMT；尚未解决挑战）+ verify-rust-std 仓库 README（挑战 #7 原子类型 / #27 Arc 仍 Open，2026-08 抓取） — model-checking 组织 / arXiv:2510.01072，2024-10-09 / 2025-10-01 / 2026-08-02. https://github.com/model-checking/verify-rust-std ; https://github.com/model-checking/verify-rust-std/issues/108 ; https://arxiv.org/html/2510.01072v1
[^5^]: Miri: Practical Undefined Behavior Detection for Rust（POPL 2026，Proc. ACM Program. Lang. Vol. 10, Article 48） — Jung, Kimock, Poveda, Sánchez Muñoz, Scherer, Wang（ETH Zurich 等），2026-01. https://research.ralfj.de/papers/2026-popl-miri.pdf
[^6^]: Adopting the FLS（Ferrocene Language Specification 2025-03 捐赠 Rust 项目） — Rust 官方博客 / Ferrous Systems+AdaCore，2025-03. https://blog.rust-lang.org/ ; https://github.com/rust-lang/fls
[^7^]: Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development（微软 CVE 内存占比近 70%→约 50%，2016–2023 图 1） — NSA+CISA 联合 CSI U/OO/172709-25，2025-06-24（NSA/CISA 发布日；PDF 文件路径含 Jun/23）. https://media.defense.gov/2025/Jun/23/2003742198/-1/-1/0/CSI_MEMORY_SAFE_LANGUAGES_REDUCING_VULNERABILITIES_IN_MODERN_SOFTWARE_DEVELOPMENT.PDF
[^8^]: Regulation (EU) 2024/2847（CRA；Art.14 报告义务 2026-09-11 起适用，主要义务 2027-12-11） — EUR-Lex / 欧盟，OJ 2024-11-20. https://eur-lex.europa.eu/eli/reg/2024/2847/oj
[^9^]: 'Against the Void'（IEEE S&P 2024）：88% 审计不足半次、51% 用过工具、vet 仅 7% — McCormack et al., arXiv:2404.02230，2023-10/2024. https://arxiv.org/abs/2404.02230
[^10^]: A proactive approach to more secure code（微软每年 CVE 约 70% 为内存安全问题，2006–2018 口径） — Gavin Thomas / MSRC Blog，2019-07-16. https://msrc.microsoft.com/blog/2019/07/a-proactive-approach-to-more-secure-code
[^11^]: The Case for Memory Safe Roadmaps（"约 2/3 软件漏洞源于内存不安全编码"；五眼 8 机构联署） — CISA/NSA/FBI/ACSC/CCCS/NCSC-UK/NCSC-NZ/CERT-NZ，2023-12-06. https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps
[^12^]: Eliminating memory safety vulnerabilities at the source（Android 内存安全漏洞占比 2019 年 76%→2024 年 24%） — Vander Stoep & Rebert / Google Security Blog，2024-09-25. https://security.googleblog.com/2024/09/eliminating-memory-safety-vulnerabilities-Android.html
[^13^]: The Rust Reference, "The unsafe keyword"（17.1 章 RFC 2585 define/discharge 证明义务框架） — rust-lang 官方文档，访问 2026-08-02（RFC 2020-10 接受）. https://doc.rust-lang.org/reference/unsafe-keyword.html ; https://github.com/rust-lang/rfcs/blob/master/text/2585-unsafe-block-in-unsafe-fn.md
[^14^]: Tree Borrows (PLDI 2025 论文, PACMPL 9 Article 188) — Villani, Hostert, Dreyer, Jung，2025-06. https://dl.acm.org/doi/10.1145/3735592
[^15^]: The Rust Book, ch.20.1 "Unsafe Rust"（五种超能力；unsafe 不关闭借用检查） — Rust 项目官方文档，访问 2026-08-02. https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html
[^16^]: The Rust Reference, "Behavior considered undefined"（UB 清单十条顶层条目、六处未定标注、soundness 操作化定义、const provenance 新规） — Rust 项目官方文档，访问 2026-08-02. https://doc.rust-lang.org/reference/behavior-considered-undefined.html
[^17^]: The Rust Reference, "Behavior not considered unsafe"（死锁/泄漏/不跑析构/整数溢出非 UB） — Rust 项目官方文档，访问 2026-08-02. https://doc.rust-lang.org/reference/behavior-not-considered-unsafe.html
[^18^]: RFC 3559 "Rust has provenance"（指针=地址+provenance；strict provenance API 于 1.84 稳定） — Ralf Jung / rust-lang/rfcs，2023-11-22；访问 2026-08-02. https://rust-lang.github.io/rfcs/3559-rust-has-provenance.html
[^19^]: Unsafe Code Guidelines Reference, Glossary（soundness 全称量化定义）+ Reference UB 页首段操作化表述 — rust-lang UCG / Reference，2019 起维护；访问 2026-08-02. https://rust-lang.github.io/unsafe-code-guidelines/glossary.html
[^20^]: Rust Reference unsafety 章 / The Rustonomicon 1.1 How Safe and Unsafe Interact（unsafe 创设/解除证明义务） — rust-lang 官方文档，访问 2026-08-02. https://doc.rust-lang.org/nomicon/safe-unsafe-meaning.html ; https://doc.rust-lang.org/reference/
[^21^]: Rust Blog, "Announcing Rust 1.85.0 and Rust 2024"（语言侧四项收紧 + std 三函数转 unsafe） — Rust 项目官方博客，2025-02-20. https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/
[^22^]: The Rust Edition Guide, "Unsafe extern blocks"（RFC 3484；safe/unsafe 项级粒度） — Rust 项目官方文档，访问 2026-08-02. https://doc.rust-lang.org/nightly/edition-guide/rust-2024/unsafe-extern.html
[^23^]: The Rust Edition Guide, "Unsafe attributes"（RFC 3325；export_name="malloc" safe 致崩案例） — Rust 项目官方文档，访问 2026-08-02. https://doc.rust-lang.org/nightly/edition-guide/rust-2024/unsafe-attributes.html
[^24^]: The Rust Edition Guide, "Disallow references to static mut"；rust-lang/rust #123758、#128794（即时 UB；hard error 降格 deny-by-default；不提供自动迁移） — Rust 项目官方文档 / GitHub issues，访问 2026-08-02；#128794 2024-08-07. https://doc.rust-lang.org/nightly/edition-guide/rust-2024/static-mut-references.html ; https://github.com/rust-lang/rust/issues/128794
[^25^]: rustc lint 文档 UNSAFE_OP_IN_UNSAFE_FN（2021 前 allow、2024 起 warn，升级仍在考虑） — rust-lang 官方 lint 文档，访问 2026-08-02. https://doc.rust-lang.org/stable/nightly-rustc/rustc_lint/builtin/static.UNSAFE_OP_IN_UNSAFE_FN.html
[^26^]: rust-lang/rust tracking issue #124951 与 #116410（invalid_reference_casting：Clippy 上收、1.73 deny、ZST/DST 误报、"是否默认沉默"开放问题） — rust-lang GitHub issues，#124951 2024-05-10；#116410 2023-10-03. https://github.com/rust-lang/rust/issues/124951 ; https://github.com/rust-lang/rust/issues/116410
[^27^]: From Stacks to Trees: A new aliasing model for Rust — Ralf Jung (ralfj.de)，2023-06-02. https://www.ralfj.de/blog/2023/06/02/tree-borrows.html
[^28^]: Tree Borrows 规范工作文档 (wip/tree-borrows.md) — rust-lang Unsafe Code Guidelines，访问 2026-08-02. https://github.com/rust-lang/unsafe-code-guidelines/blob/master/wip/tree-borrows.md
[^29^]: What's 'new' in Miri (and also, there's a Miri paper!)（Miri+GenMC 集成进展） — Ralf Jung（Miri 第一作者博客），2025-12-22. https://www.ralfj.de/blog/2025/12/22/miri.html
[^30^]: Miri README（SB 默认、TB 旗标与 Experimental 警告） — rust-lang/miri，访问 2026-08-02. https://github.com/rust-lang/miri/blob/master/README.md
[^31^]: Tree Borrows (PLDI 2025 论文 PDF §3 protectors) — Villani et al.，2025-06. https://research.ralfj.de/papers/2025-pldi-tree-borrows.pdf
[^32^]: 真实案例：nalgebra#1588 与 URLO "Tree vs stack borrows" — nalgebra / Rust 用户论坛，2026-02-18 / 2024-04-17. https://github.com/dimforge/nalgebra/issues/1588 ; https://users.rust-lang.org/t/tree-vs-stack-borrows/110076
[^33^]: UCG #573: Strengthening Tree Borrows so that we can discard Stacked Borrows — rust-lang/unsafe-code-guidelines (Ralf Jung)，2025-06-09 开，访问 2026-08-02 仍 open，2026-10-27 复核标题不变、仍 open（最近更新 2026-04-27）. https://github.com/rust-lang/unsafe-code-guidelines/issues/573
[^34^]: UCG #584: LLVM writable 属性之争 — rust-lang/unsafe-code-guidelines (Ralf Jung)，2025，访问 2026-08-02. https://github.com/rust-lang/unsafe-code-guidelines/issues/584
[^35^]: rust-lang/rust #132898: ReferencePropagation miscompile (I-miscompile) — rust-lang/rust (Ralf Jung 报告)，2024-11-11 开，截至 2026-08 仍 open. https://github.com/rust-lang/rust/issues/132898
[^36^]: MiniRust 仓库 README（架构、内存接口、与 Reference 差异） — minirust/minirust (Ralf Jung)，访问 2026-08-02. https://github.com/minirust/minirust
[^37^]: A Vision for a Rust Formal Specification — Nadrieril，2026-06-16. https://nadrieril.github.io/blog/2026/06/16/formal-spec-vision.html
[^38^]: Program management update — October 2025（FLS 团队 2025-10-31 首次会议、as-implemented 定位） — Inside Rust Blog，2025-11-19. https://blog.rust-lang.org/inside-rust/2025/11/19/program-management-update--october-2025/
[^39^]: Rust Project Goals 2026（Stabilize FLS Release Cadence；Normative Documentation for Sound unsafe Rust；BorrowSanitizer #624） — rust-lang/rust-project-goals，2026-05. https://rust-lang.github.io/rust-project-goals/2026/ ; https://github.com/rust-lang/rust-project-goals/issues/624
[^40^]: BorrowSanitizer 月度状态更新与 LLVM RFC — borrowsanitizer.com / discourse.llvm.org，2026-01-08 → 2026-05-29. https://borrowsanitizer.com/status/january_2026.html ; https://discourse.llvm.org/t/rfc-experimental-support-for-borrowsanitizer/90938 ; https://github.com/BorrowSanitizer/bsan
[^41^]: rust-lang/miri GitHub README（检测能力清单、soundness 声明、SB 默认/TB 可选） — rust-lang 官方，访问 2026-08-02. https://github.com/rust-lang/miri/
[^42^]: （二手）The Rust Developer's Toolbox: Best Static Code Analysis Tools（Miri "10-50x slower" 二手性能口径） — IN-COM，2026-06-04. https://www.in-com.com/blog/the-rust-developers-toolbox-best-static-code-analysis-tools/（置信度：低/待核实）
[^43^]: Yuga: Automatically Detecting Lifetime Annotation Bugs in the Rust Language（Miri 27/27 vs 0/27 实验） — arXiv 作者团队，v2（2024 前后）. https://arxiv.org/html/2310.08507v2
[^44^]: A Study of Undefined Behavior Across Foreign Function Boundaries in Rust Libraries（MiriLLI，46 处 UB/37 库 v6 口径） — McCormack et al.（CMU），v6（2024-2025）. https://arxiv.org/pdf/2404.11671v6
[^45^]: RUSTMC: Extending the GENMC stateless model checker to Rust — Pearce, Lange, O'Keeffe（Royal Holloway），2025-02-10. https://arxiv.org/abs/2502.06293
[^46^]: tokio-rs/loom GitHub README（"既不 sound 也不 complete"声明） — tokio-rs 官方，访问 2026-08-02. https://github.com/tokio-rs/loom
[^47^]: awslabs/shuttle GitHub README（soundness–scalability 权衡） — AWS 官方，访问 2026-08-02. https://github.com/awslabs/shuttle
[^48^]: Rust Unstable Book "sanitizer" 页 + rust-lang/rust issue #123615（sanitizer 稳定化路线图） — rust-lang 官方，访问 2026-08-02. https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html ; https://github.com/rust-lang/rust/issues/123615
[^49^]: cargo-careful GitHub README（定位：普通测试与 Miri 之间的档） — Ralf Jung，访问 2026-08-02. https://github.com/RalfJung/cargo-careful
[^50^]: microsoft/oxidizer GitHub README（PR 门禁：Miri 多别名模型矩阵 + Loom + Bolero） — Microsoft 官方，访问 2026-08-02. https://github.com/microsoft/oxidizer
[^51^]: Qiskit CONTRIBUTING.md（unsafe 必须配 Rust 测试、Miri 进 CI） — Qiskit 官方，访问 2026-08-02. https://github.com/Qiskit/qiskit/blob/main/CONTRIBUTING.md
[^52^]: Kani: A Model Checker for Rust（ASE 2026 论文；架构、生产案例、11 bug 总账、Hifitime） — Delmas et al.（AWS 等），2026-07-01. https://arxiv.org/html/2607.01504v1
[^53^]: Using Kani to Validate Security Boundaries in AWS Firecracker（rate limiter 5 bug + VirtIO 1 bug） — Kani 官方博客（AWS），2023-08-31. https://model-checking.github.io/kani-verifier-blog/2023/08/31/using-kani-to-validate-security-boundaries-in-aws-firecracker.html
[^54^]: How s2n-quic uses Kani to inspire confidence（Bolero 双用；fuzz 16,777,216 次无果 vs Kani 20 秒） — Kani 官方博客（AWS），2023-05-30. https://model-checking.github.io/kani-verifier-blog/2023/05/30/how-s2n-quic-uses-kani-to-inspire-confidence.html
[^55^]: Formal Verification of Cryptographic Software at AWS（NIST 文档：s2n-tls 为 C 实现用 CBMC/SAW，Kani 用于 s2n-quic） — NIST，未标注（访问 2026-08）. https://www.nist.gov/document/formal-verification-cryptographic-software-aws-current-practices-and-future-trends
[^56^]: Verifying the Rust Standard Library (arXiv:2606.17374) — Cook et al. (AWS)，2026（数据快照 nightly-2025-10-08，口径至 2026-03）. https://arxiv.org/html/2606.17374v1
[^57^]: Annotating and Auditing the Safety Properties of Unsafe Rust（21 安全标签五类、覆盖 96.1% 公开 unsafe API；审计发现的 27 API/61 处文档缺陷修复并入 std） — arXiv:2504.21312v2，2026-04-25. https://arxiv.org/html/2504.21312v2
[^58^]: The Kani Book: Undefined behaviour / Rust feature support（不检测数据竞争、不建模别名、不支持并发/汇编） — Kani 官方文档，访问 2026-08-02. https://model-checking.github.io/kani/undefined-behaviour.html
[^59^]: Expanding the Rust Formal Verification Ecosystem: Welcoming ESBMC（CI 上线、Approved Tools、Kani 可选后端计划） — Rust Foundation 官方博客，2025-08-07. https://rustfoundation.org/media/expanding-the-rust-formal-verification-ecosystem-welcoming-esbmc/
[^60^]: Place Capability Graphs: A General-Purpose Model of Rust's Ownership and Borrowing Guarantees (OOPSLA 2025) — Grannan et al., arXiv，2025-08-12. https://arxiv.org/html/2503.21691v5
[^61^]: verify-rust-std Issue #493 (Add Tool: Creusot) + Using Ghost Ownership to Verify Union-Find and Persistent Arrays in Rust (CPP 2026) — model-checking/verify-rust-std; Golfouse et al., HAL，2025-09-16 / CPP 2026. https://github.com/model-checking/verify-rust-std/issues/493 ; https://hal.science/hal-05396946v1/file/main.pdf
[^62^]: Creusot Devlog 0.9.0 (AtomicInvariant 并发支持) 与 CHANGELOG — creusot-rs，2026-01-19 / 2026-06-12. https://devlog.creusot.rs/2026-01-19/ ; https://github.com/creusot-rs/creusot/blob/master/CHANGELOG.md
[^63^]: OSDI 2024 Jay Lepreau 最佳论文（Anvil/VeriSMo） — UIUC Siebel School; Microsoft Research，2024-07. https://siebelschool.illinois.edu/news/jay-lepreau-best-paper ; https://www.microsoft.com/en-us/research/event/osdi-2024/publications/
[^64^]: Asterinas 用 Verus 验证内核内存管理（asterinas/vostd） — Asterinas 官方博客/GitHub，2025-02-13. https://asterinas.github.io/2025/02/13/towards-practical-formal-verification-for-a-general-purpose-os-in-rust.html ; https://github.com/asterinas/vostd
[^65^]: VerusBelt: PLDI 2026 杰出论文+杰出 artifact（Iris/Rocq 机械化 soundness） — Hance et al., PLDI 2026 / iris-project.org，2026-06. https://pldi26.sigplan.org/details/pldi-2026-papers/82/ ; https://iris-project.org/pdfs/2026-pldi-verusbelt.pdf
[^66^]: The VeriFast for Rust Reference（分离逻辑模块化验证 unsafe） — VeriFast 官方文档 (KU Leuven)，2026-08-02 访问. https://verifast.github.io/verifast/rust-reference/
[^67^]: Foundational VeriFast: Pragmatic Certification via Hinted Mirroring — Bart Jacobs, arXiv:2601.13727，2026-01. https://arxiv.org/pdf/2601.13727
[^68^]: Flux: Liquid Types for Rust（PLDI 2023 摘要：规约减半、注解开销最高 25%/均值 9%→零） — Lehmann et al., PLDI 2023，2023-06-21. https://pldi23.sigplan.org/details/pldi-2023-pldi/64/Flux-Liquid-Types-for-Rust
[^69^]: Aeneas/Charon 管道架构与后端（LLBC→Lean/Coq/F*/HOL4） — AeneasVerif 官网与 README，2026-08-02 访问. https://aeneasverif.github.io/projects/ ; https://github.com/AeneasVerif/aeneas
[^70^]: Verifying Rust Cryptography in SymCrypt（ML-KEM/SHA-3，5,529 行代码 vs 58,377 行证明） — Microsoft Research Blog，2026-07-13. https://www.microsoft.com/en-us/research/blog/verifying-rust-cryptography-in-symcrypt-from-standards-to-code/
[^71^]: 六工具 GitHub 仓库元数据实测（pushed_at/stars） — GitHub API（prusti-dev/creusot/verus/verifast/flux/aeneas/charon），2026-08-02 查询. https://api.github.com/
[^72^]: Rudra: Finding Memory-Safety Bugs in Rust at the Ecosystem Scale（SOSP'21；264 bugs/76 CVEs；RustSec 覆盖 96/187=51.3%） — Bae et al., SOSP 2021; sslab-gatech/Rudra-Artifacts，2021. https://github.com/sslab-gatech/Rudra
[^73^]: TypePulse: Detecting Type Confusion Bugs in Rust Programs（transmute 降级致 Rudra 盲区） — USENIX Security 2025, arXiv:2502.03271，2025. https://arxiv.org/html/2502.03271v1
[^74^]: Mitigating False Positives in Static Memory Safety Analysis of Rust via RL（Rudra 复刻精度 25.6%，4,879 警告人工标注） — EASE 2026, arXiv:2605.04000，2026-05-06. https://arxiv.org/html/2605.04000v2
[^75^]: Rudra 仓库归档（archived 2026-04-02，锁定 nightly-2021-10-21） — GitHub API repos/sslab-gatech/Rudra，2026-08-02 查询. https://api.github.com/repos/sslab-gatech/Rudra
[^76^]: MIRAI 归档（2024-08-22）与 Endor Labs fork 续命（2026-05 仍 push） — facebookexperimental/MIRAI Overview; GitHub API endorlabs/MIRAI，2024-08 / 2026-08-02 查询. https://github.com/facebookexperimental/MIRAI ; https://api.github.com/repos/endorlabs/MIRAI
[^77^]: Charon: An Analysis Framework for Rust（稳定 IR 抽象层动机） — Ho et al., arXiv:2410.18042，2024. https://arxiv.org/abs/2410.18042
[^78^]: RAPx（复旦大学 Artisan-Lab；0.7.30 六周 15 版；Z3 契约验证） — safer-rust/RAPx GitHub; crates.io API，2026-08-02 查询. https://github.com/safer-rust/RAPx ; https://crates.io/crates/rapx
[^79^]: RUXt: Rust Incorrectness Separation Logic (ECOOP 2025, LIPIcs 333) — Carrott, Ayoun, Raad，2025-06. https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ECOOP.2025.5
[^80^]: Clippy 官方 lint 文档（847 lints；unsafe 相关 lint 组/默认级别逐项提取） — rust-lang.github.io/rust-clippy，2026-08-02 抓取. https://rust-lang.github.io/rust-clippy/master/
[^81^]: Rust Edition Guide: unsafe_op_in_unsafe_fn（2024 edition 默认 warn）；RFC 3325 unsafe attributes — rust-lang，2026-08 访问. https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html
[^82^]: Semgrep supported-languages 文档（Rust GA，40+ Pro 规则；Supply Chain GA） — Semgrep 官方文档; GitLab issue #439046，2026-07-30 快照. https://docs.semgrep.dev/supported-languages
[^83^]: CodeQL Rust 支持 GA（2025-10-27，CLI 2.23.3；OWASP Top 10 除 A06） — GitHub Blog; community discussion #178177，2025-06-30 / 2025-10-27. https://github.blog/changelog/2025-06-30-codeql-support-for-rust-now-in-public-preview/ ; https://github.com/orgs/community/discussions/178177
[^84^]: cargo-geiger README（计数定位、Intended Use；issues #447/#81 口径缺陷） — geiger-rs/cargo-geiger，2026-08-02 访问. https://github.com/geiger-rs/cargo-geiger ; https://github.com/geiger-rs/cargo-geiger/discussions/302
[^85^]: RustSec Advisory Database（informational-unsound 分类；--deny unsound；2025–2026 条目加速） — rustsec.org，2026-08 访问. https://rustsec.org/advisories/ ; https://rustsec.org/keywords/unsound.html ; https://rustsec.org/categories/memory-corruption.html
[^86^]: RustXec（MSR 2026）：515 条公告（含 89 unsound、117 unmaintained、10 重复，余 299；2021.01–2025.04） — Ji et al., Virginia Tech/Wake Forest，2026-04. https://people.cs.vt.edu/xinw/publications/RustXec26-B38KjKAe.pdf
[^87^]: cargo-vet registry.toml（9 家机构审计集）与官方书册（不可传递导入） — mozilla/cargo-vet，2026-08-02 访问. https://raw.githubusercontent.com/mozilla/cargo-vet/main/registry.toml ; https://mozilla.github.io/cargo-vet/importing-audits.html
[^88^]: （二手，项目自述）Argos THREAT_MODEL.md（导入杠杆：142 完全审计+6 部分+565 豁免/618） — sovright/argos GitHub，2026-05-27. https://github.com/sovright/argos/blob/main/docs/THREAT_MODEL.md
[^89^]: Auditing Rust Crates Effectively（Cargo Scan；中位数 0.2% LoC；3,434/10K pure；axum-forbid 批评） — Zoghbi et al., ESOP 2026, arXiv:2602.06466，2026-02-06. https://arxiv.org/abs/2602.06466
[^90^]: Trail of Bits skills 仓库 rust-review 插件（AI 审计入场） — trailofbits/skills GitHub，2026-01-14. https://github.com/trailofbits/skills
[^91^]: Awesome-Rust-Checker（各工具最后提交时间：geiger 2025-08-31、vet 2026-04-19、deny 2026-06-05、semver-checks 2026-05-31） — CodeSentryAI/Awesome-Rust-Checker，2026-06-06. https://github.com/CodeSentryAI/Awesome-Rust-Checker
[^92^]: cargo-crev releases（v0.27.1 仍发版）与采用困境评论 — crev-dev/cargo-crev; llbbl.blog，2026-08 访问 / 2026-05. https://github.com/crev-dev/cargo-crev/releases ; https://llbbl.blog/categories/supply-chain/
[^93^]: cargo-semver-checks（v0.42.0，177 lint，target_feature 研究发现语言级 unsoundness） — obi1kenobi/cargo-semver-checks; predr.ag 博客，2025-04-22 / 2025-07-05. https://github.com/obi1kenobi/cargo-semver-checks/releases ; https://predr.ag/blog/unsoundness-and-accidental-features-in-target-feature/
[^94^]: The (successful) end of the kernel Rust experiment — LWN.net (Jonathan Corbet)，2025-12-10. https://lwn.net/Articles/1049831/
[^95^]: LPC 2025: Rust for Linux 官方幻灯（实验收官、稳定化路线图、Android 16 ashmem） — Miguel Ojeda / LPC 2025，2025-12-11. https://lpc.events/event/19/contributions/2068/attachments/1859/3981/2025-12-11%20-%20LPC%202025%20-%20Rust%20for%20Linux.pdf
[^96^]: General Information — Rust in the Linux kernel（三层架构、leaf 模块禁令） — docs.kernel.org，检索于 2026-08. https://docs.kernel.org/rust/general-information.html
[^97^]: Coding Guidelines — Rust（// SAFETY: 强制条款、# Safety 契约、unsafe_op_in_unsafe_fn） — docs.kernel.org / dri.freedesktop.org 镜像，检索于 2026-08. https://dri.freedesktop.org/docs/drm/rust/coding-guidelines.html
[^98^]: kernel::device::Device 与 ARef/AlwaysRefCounted 文档及 rust/kernel/types.rs 源码 — rust.docs.kernel.org / codebrowser.dev，2026-03 快照，检索于 2026-08. https://rust.docs.kernel.org/kernel/device/struct.Device.html
[^99^]: Pre-RFC: Rust Safety Standard - Unsafe Code Guidelines — rust-internals，2026-01-31. https://internals.rust-lang.org/t/pre-rfc-rust-safety-standard/23963
[^100^]: gccrs 2026-03 月度报告（三大里程碑、RustConf 2026 内核议题、Drop 语义） — gccrs 项目，2026-03-18. https://rust-gcc.github.io/2026/04/13/2026-03-monthly-report.html
[^101^]: （二手）First Linux Kernel Rust CVE（GKH social.kernel.org 原文转录、"just causes a crash"、同日 159 个 C CVE） — It's FOSS，2025-12-16 至 2025-12-18. https://itsfoss.com/news/first-linux-kernel-rust-cve/
[^102^]: （二手，评论博客）CVE-2025-68260 Deep Dive: It's Concurrency Semantics Failing — Penligent，2025-12-22. https://www.penligent.ai/hackinglabs/cve-2025-68260-deep-dive-linux-kernels-first-rust-cve-isnt-rust-failing-its-concurrency-semantics-failing/
[^103^]: A Rust implementation of Android's Binder（LPC 2023，Ryhl 论 unsafe 集中化与漏洞降级） — LWN.net，2023-11-30. https://lwn.net/Articles/953116/
[^104^]: Latest Linux 6.19 Code Fixes Rust Binder Driver（list_lru per-cgroup 锁漂移） — Phoronix，2026-01-11. https://www.phoronix.com/news/Linux-6.19-rc5-char-misc
[^105^]: （二手）Microsoft is rewriting Windows in Rust in small bites（RustConf 2025 Russinovich：win32kbase_rs.sys、DirectWriteCore 15.4 万行） — The Stack，2026-01-01. https://www.thestack.technology/rewriting-windows-in-rust/（置信度：低/待核实）
[^106^]: RTIC Book（SRP 编译期无死锁/无竞争）；Embassy — Rust + async embedded — rtic.rs / embassy.dev，检索于 2026-08. https://rtic.rs/dev/book/en/ ; https://embassy.dev/
[^107^]: Tyr 2026 上游化路线图（含 Airlie DRM"新驱动强制 Rust"表态） — LWN.net（Daniel Almeida）；DEVCLASS 峰会报道，2026-02-03 / 2025-12-15. https://lwn.net/Articles/1056417/ ; https://www.devclass.com/development/2025/12/15/rust-boosted-by-permanent-adoption-for-linux-kernel-code/1725322
[^108^]: Software Memory Safety（网络安全信息单，MSL 名单 C#/Go/Java/Ruby/Rust/Swift，无 Python） — NSA，2022-11-10. https://media.defense.gov/2022/Nov/10/2003112742/-1/-1/0/CSI_SOFTWARE_MEMORY_SAFETY.PDF
[^109^]: The Case for Memory Safe Roadmaps（五眼 8 机构联署，无德国；MSL 列表首增 Python） — CISA/NSA/FBI/ACSC/CCCS/NCSC-UK/NCSC-NZ/CERT-NZ，2023-12-06. https://media.defense.gov/2023/Dec/06/2003352724/-1/-1/0/THE-CASE-FOR-MEMORY-SAFE-ROADMAPS-TLP-CLEAR.PDF
[^110^]: Back to the Building Blocks: A Path Toward Secure and Measurable Software（归档地址；C/C++ 定性、点名 Rust） — White House ONCD，2024-02-26. https://bidenwhitehouse.archives.gov/wp-content/uploads/2024/02/Final-ONCD-Technical-Report.pdf
[^111^]: Product Security Bad Practices 草案（含 2026-01-01 硬性表述） — CISA/FBI，2024-10-16. https://www.ic3.gov/CSA/2024/241016-2.pdf
[^112^]: Product Security Bad Practices 定稿（删除硬性日期，改为"2025 年底前"，non-binding；截至 2026-08 无执法） — CISA/FBI，2025-01-17. https://www.ic3.gov/CSA/2025/250117.pdf
[^113^]: EU Cyber Resilience Act: 24-Hour Reporting Duties Start September 11, 2026 — Jones Day，2026-07-30. https://www.jonesday.com/en/insights/2026/07/eu-cyber-resilience-act-24hour-reporting-duties-start-september-11-2026
[^114^]: Memory-Unsafe Code Is a Liability（BSI NIS-2 指南点名 Rust 的唯一可查来源） — corrode.dev（Rust 咨询商，有立场），2026-06-12. https://corrode.dev/blog/memory-safety/（置信度：低/待核实）
[^115^]: DARPA Backs Effort to Convert C to Rust（ForCLift，$5M，UIUC/UW-Madison/UC Berkeley/爱丁堡） — Univ. of Illinois CSL，2025-07-15. https://csl.illinois.edu/news-and-media/translating-legacy-code-for-a-safer-future-darpa-backs-effort-to-convert-c-to-rust
[^116^]: TRACTOR 项目页与 Benchmarks（MIT LL 承担 T&E，每六个月发布基准） — DARPA / MIT Lincoln Laboratory，2024-10-18 更新. https://www.darpa.mil/program/translating-all-c-to-rust ; https://www.ll.mit.edu/tractor
[^117^]: Inside DARPA's TRACTOR Program（"95% 自动化、unsafe<5%"指标的唯一来源） — IDST（非官方防务媒体），2025-11-22. https://idstch.com/cyber/%F0%9F%A7%A0-the-memory-safety-revolution-inside-darpas-tractor-program-to-automate-c-to-rust-transpilation/（置信度：低/待核实）
[^118^]: IEC 61508 (SIL 2) Certification for Rust Core Library Subset（工具链 ASIL D/SIL 3/62304 Class C 口径） — Ferrous Systems，2025-12-03. https://ferrous-systems.com/blog/ferrocene-libcore-news-release/
[^119^]: Canonical releases Ubuntu 25.10 Questing Quokka（默认 sudo-rs 与 Rust coreutils） — Canonical 官方博客，2025-10-09. https://ubuntu.com/blog/canonical-releases-ubuntu-25-10-questing-quokka
[^120^]: Debian demands Rust or rust in peace for legacy ports（Klode 邮件：APT 硬 Rust 依赖不早于 2026-05） — The Register（转录 debian-devel 邮件原文），2025-11-03. https://www.theregister.com/software/2025/11/03/debian-demands-rust-or-rust-in-peace-for-legacy-ports/
[^121^]: ANSSI Secure Rust Guidelines §4.2 Rule R10 (LANG-UNSAFE)：三类允许场景 + #![forbid(unsafe_code)] — ANSSI 官方指南，v1.0 2020-09，持续更新（访问 2026-08-02）. https://anssi-fr.github.io/rust-guide/04_language.html
[^122^]: forbid 作为"100% Safe Rust"供应链信号（async-broadcast、mdf4-rs） — lib.rs / GitHub README，2024-12-23 / 2025-12-19. https://lib.rs/crates/async-broadcast ; https://github.com/reneherrero/mdf4-rs
[^123^]: The Rustonomicon 1.3 Working with Unsafe（soundness 非局部，模块私有性唯一防弹边界） — rust-lang 官方文档，访问 2026-08-02. https://doc.rust-lang.org/nomicon/working-with-unsafe.html
[^124^]: Ralf Jung, "The Scope of Unsafe"（abstraction safety） — 个人博客，2016-01-09. https://www.ralfj.de/blog/2016/01/09/the-scope-of-unsafe.html
[^125^]: （二手，个人博客）Pavlo Myroniuk, "Safety Comments Matter"（一块一操作、SAFETY 注释要素）；heapless issue #562 — 个人博客 / GitHub issue，2025-05-31 / 2025-04-26. https://tbt.qkation.com/posts/safety-comments-matter/ ; https://github.com/rust-embedded/heapless/issues/562
[^126^]: Linux 6.12.19-rc1 stable patch "rust: enable clippy::undocumented_unsafe_blocks lint"（Miguel Ojeda；2024-09 合入主线、2025-03 回移植） — kernel.org lore，2025-03-10. https://lore.kernel.org/stable/20250310170457.880793137@linuxfoundation.org/t/
[^127^]: （二手，个人博客）Jack Wrenn, "The Three Basic Rules of Safety Hygiene" — 个人博客，2025-02-06. https://jack.wrenn.fyi/blog/safety-hygiene/
[^128^]: Clippy lints 官方索引（undocumented_unsafe_blocks、missing_safety_doc、unsafe_op_in_unsafe_fn、transmute 专项族 9 项） — rust-lang 官方，访问 2026-08-02. https://rust-lang.github.io/rust-clippy/master/index.html
[^129^]: rust-lang/rust issue #139013 "Pin is unsound due to the literal constructor"（公开字段绕过 Pin::new_unchecked；未修复） — GitHub issue，2025-03-27. https://github.com/rust-lang/rust/issues/139013
[^130^]: Characterizing Unsafe Code Encapsulation（interior unsafe 封装研究，字面量构造缺陷） — 复旦 Hui Xu 组，arXiv:2406.07936，2024-06-03. https://arxiv.org/html/2406.07936v1
[^131^]: std::ptr::NonNull 官方 API 文档（协变、"不确定就用 *mut T"、PhantomData 不变性补救） — rust-lang 官方文档，页面日期 2026-07-14. https://doc.rust-lang.org/std/ptr/struct.NonNull.html
[^132^]: The Rustonomicon 3.10 PhantomData（模式表；RFC 1238 后 PhantomData<T> 对 dropck 多余） — rust-lang 官方文档，访问 2026-08-02. https://doc.rust-lang.org/nomicon/phantom-data.html
[^133^]: alloc/raw_vec 源码（unsafe impl<#[may_dangle] T> Drop；ZST dangling 处理） — rust-lang 源码，2025-12-06. https://doc.rust-lang.org/nightly/src/alloc/raw_vec/mod.rs.html
[^134^]: std::mem::MaybeUninit 官方 API 文档（assume_init_mut 三个 Incorrect 示例；zeroed 仅限全零合法类型） — rust-lang 官方文档，页面日期 2026-07-14. https://doc.rust-lang.org/std/mem/union.MaybeUninit.html
[^135^]: std::mem::uninitialized 官方 API 文档（1.39 废弃；"几乎所有类型调用即立即 UB"） — rust-lang 官方文档，页面日期 2026-07-14. https://doc.rust-lang.org/std/mem/fn.uninitialized.html
[^136^]: Yoshua Wuyts, "Safe Pin Projections Through View Types"；pin-project crate（PinnedDrop 替代手写 Drop） — 个人博客 / crates.io，2022-03-04 / v1.1.11 2026-02-27. https://blog.yoshuawuyts.com/safe-pin-projections-through-view-types/ ; https://crates.io/crates/pin-project
[^137^]: The Rustonomicon 7.1 Exception Safety（最小异常安全；Vec::push_all 反例；BinaryHeap Hole 模式） — rust-lang 官方文档，访问 2026-08-02. https://doc.rust-lang.org/nomicon/exception-safety.html
[^138^]: The Rustonomicon 6.3 Leaking（不得依赖析构；vec::Drain set_len(start) 泄漏放大）；Chris Krycho "Using Drop Safely in Rust" — rust-lang 官方文档 / 个人博客，访问 2026-08-02 / 2024-12-12. https://doc.rust-lang.org/nomicon/leaking.html ; https://v5.chriskrycho.com/journal/read-the-code/using-drop-safely-in-rust/
[^139^]: The Rustonomicon 8.2 Send and Sync；Mara Bos《Rust Atomics and Locks》ch.4（SpinLock<T>: Sync 需 T: Send） — rust-lang 官方文档 / URLO t/119012，访问 2026-08-02 / 2024-09-30. https://doc.rust-lang.org/nomicon/send-and-sync.html ; https://users.rust-lang.org/t/119012
[^140^]: tokio 源码 unsafe impl Send/Sync SAFETY 注释实例（RwLockReadGuard） — GitHub 源码注释，访问 2026-08-02. https://github.com/tokio-rs/tokio
[^141^]: RustSec smallvec 包页与逐条 advisory（RUSTSEC-2018-0003/0018、2019-0009/0012、2021-0003；CVE-2018-25023、CVE-2019-15551 CVSS 9.8） — RustSec / NVD，2018-09 至 2021-01（访问 2026-08-02）. https://rustsec.org/packages/smallvec.html ; https://rustsec.org/advisories/RUSTSEC-2019-0009.html ; https://nvd.nist.gov/vuln/detail/cve-2018-25023
[^142^]: RFC 3151 scoped-threads（leakpocalypse 动机；thread::scope 1.63 稳定） — rust-lang RFC 原文，2019-02-26. https://rust-lang.github.io/rfcs/3151-scoped-threads.html
[^143^]: Rust Blog "Fearless Concurrency"（thread::scoped 原始设计与移除注记） — rust-lang 官方博客，2015-04-10. https://blog.rust-lang.org/2015/04/10/Fearless-Concurrency.html
[^144^]: ANSSI Secure Rust Guidelines checklist（LIBS-VETTING-DIRECT、UNSAFE-NOUB、LANG-UNSAFE-ENCP） — ANSSI 官方，持续更新（访问 2026-08）. https://anssi-fr.github.io/rust-guide/checklist.html
[^145^]: Rust Secure Code WG, Rust Supply Chain Security Guide（tarball 审阅；IDE 打开即 proc-macro 执行风险；cargo-audit --deny unsound） — rust-secure-code 官方指南，2022-05-10（持续维护）. https://rust-secure-code.github.io/rust-supply-chain-security/dependencies.html
[^146^]: RustBelt: Securing the Foundations of the Rust Programming Language (PACMPL 2(POPL), Art. 66) — Jung, Jourdan, Krebbers, Dreyer (MPI-SWS)，2018-01. https://people.mpi-sws.org/~dreyer/papers/rustbelt/paper.pdf
[^147^]: RustBelt Meets Relaxed Memory (PACMPL 4(POPL), Art. 34) — Dang, Jourdan, Kaiser, Dreyer，2020-01. https://jhjourdan.mketjh.fr/pdf/dang2020rustbelt.pdf
[^148^]: RustHornBelt (PLDI 2022 杰出论文, DOI 10.1145/3519939.3523704) — Matsushita, Denis, Jourdan, Dreyer，2022-06. https://people.mpi-sws.org/~dreyer/papers/rusthornbelt/paper.pdf
[^149^]: RefinedRust (PACMPL 8(PLDI) Art. 192, DOI 10.1145/3656422) — Gäher, Sammler, Jung, Krebbers, Dreyer，2024-06. https://iris-project.org/pdfs/2024-pldi-refinedrust.pdf
[^150^]: A hybrid approach to semi-automated Rust verification (Gillian-Rust, arXiv:2403.15122v2, PLDI'25 扩展版) — Ayoun, Denis, Maksimović, Gardner，2024-03（v2 2025）. https://arxiv.org/html/2403.15122v2
[^151^]: A Program Logic for Tree Borrows（ETH Zürich 硕士论文） — R. Peterson，2025. https://ethz.ch/content/dam/ethz/special-interest/infk/inst-pls/plf-dam/documents/StudentProjects/MasterTheses/2025-Rudy-Thesis.pdf
[^152^]: Rust Foundation Collaborates With AWS Initiative to Verify Rust Standard Libraries（启动公告） — Rust Foundation，2024-11-20. https://rustfoundation.org/media/rust-foundation-collaborates-with-aws-initiative-to-verify-rust-standard-libraries/
[^153^]: verify-rust-std 仓库 doc/src/tools.md（Approved Tools 清单：4 批准） — model-checking/verify-rust-std，访问 2026-08-02. https://raw.githubusercontent.com/model-checking/verify-rust-std/main/doc/src/tools.md
[^154^]: verify-rust-std book: General Rules（评审与治理规则） — verify-rust-std 官方，访问 2026-08-02. https://model-checking.github.io/verify-rust-std/general-rules.html
[^155^]: KaPilot: LLM-Assisted Generation of Kani Specifications for Unsafe Rust Verification (arXiv:2607.21957) — Wang et al.，2026-07-24. https://arxiv.org/abs/2607.21957
[^156^]: KVerus: Scalable and Resilient Formal Verification Proof Generation for Rust Code (arXiv:2605.03822) — Liu et al.，2026-05. https://arxiv.org/abs/2605.03822
[^157^]: Harnessing Code Agents for Automatic Software Verification（Aria，arXiv:2607.06341） — Kan et al.，2026-07-07. https://arxiv.org/html/2607.06341v1
[^158^]: A Rust-to-Lean Verification Pipeline with AI Provers (arXiv:2605.30106) — Klaus, Tolmach, Conejero (Runtime Verification)，2026-05/07. https://arxiv.org/abs/2605.30106
[^159^]: HarnessLLM: Rust Verification Harness Generation with Large Language Models (arXiv:2607.22161) — arXiv，2026-07-24. https://arxiv.org/html/2607.22161v1
[^160^]: Verus: A Practical Foundation for Systems Verification（SOSP 2024；摘要 6.1K 行实现/31K 行证明，Figure 9 各案例证明比，直读 PDF） — Lattuada et al.，2024-11. https://par.nsf.gov//servlets/purl/10630619
[^161^]: Advancing security with Windows and Surface: Microsoft SFI report Nov 2025（"70% of the security vulnerabilities that Microsoft resolves each year"与内存安全相关） — Windows Experience Blog（Holdsworth、Abzarian），2025-11-10. https://blogs.windows.com/windowsexperience/2025/11/10/advancing-security-with-windows-and-surface-microsoft-sfi-report-nov-2025/
