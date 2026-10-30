# Research: DNS 缓存语义差分测试的最近邻工作与论文定位

- Query: 核验 SymCC、DNS 缓存/状态感知差分测试及混合 fuzzing 最近邻工作，确定可辩护主线、已被覆盖的声称与实验缺口。
- Scope: mixed；只读本地计划、论文材料与相关代码，检索一手论文及官方项目页面；不实施、不运行基线。
- Date: 2026-10-30
- 核验日期：本文全部外部条目均于 **2026-10-30** 检索或读取。主比较收敛到下列 **8 项论文/项目**；不声称穷尽截至当日的文献。

## Findings

### 1. 结论先行

**最近邻不是普通 DNS packet fuzzer，而是 ResolverFuzz、ResolFuzz 和 BGF-DR。现有计划中的“查询/响应联合生成、多解析器差分、缓存观察、启发式过滤、指纹聚类”均已有直接先例；连“测试后查询缓存”和“重复重放排除非确定差异”，ResolFuzz 也已明确实现。**

[INFERENCE] 最可辩护的一条主线是：

> **面向 DNS 缓存安全语义的受控差分重放与可复核测量：研究单一 producer 产生的统一有界 transcript，在异构 resolver 上如何保持可比较、如何区分状态失配与真实语义差异，以及缓存变化何时真正影响后续查询。SymCC 是可消融的输入增强器，不预设为论文核心创新。**

这是一条需要实验兑现的定位建议，不是已经证明的创新性结论。贡献应落在**可量化的比较偏差、可信的语义判定、可复核的新案例/测量发现**，而不是给已有组合换名称。若只剩 C++ 重写、六个适配器与报告流水线，目前没有足够证据把它写成新的研究方法。

### 2. 本地文件与代码依据

以下路径相对 `/home/egoist/work`；行号为本轮读取时的位置。

| 文件 | 内容及论文定位依据 |
| --- | --- |
| `symcc/docs/DNSPoisonFuzzingPlan.md:5-18` | 既定主线为 transcript-guided hybrid fuzzing、单一 BIND9 producer、多 resolver 同步 replay；DST1 包含 query、forged response、post-check。 |
| `symcc/docs/DNSPoisonFuzzingPlan.md:25-29,49-53` | RQ1–RQ5、重复实验和 case study 要求；已点名 ResolverFuzz/BGF-DR/AFLNet/StateAFL，但不是核验过的相关工作论证。 |
| `symcc/docs/DNSPoisonPaperResultsDraft.md:3,21-44,212-224` | 草稿明确原始矩阵在当前树缺失、数值仅供历史推演；修正后的同源 wire query 对照也能进入 fetch 路径；未观测到 hybrid 变体差异。 |
| `symcc/docs/DNSPoisonPaperMaterialStatus.md:13-33` | 记录更大历史语料、变体间差异为零及曾通过审计的说法；本轮未复核其原始产物，不能压过结果草稿的证据警告。 |
| `symcc/docs/RQ3GateContrast20260813.md:14-30` | 短预算 gate 对照中 `high_value_new_coverage` 两组均为 0；不能把高价值样本被处理当成新增覆盖或漏洞增益。 |
| `symcc/docs/RQ4Fingerprint20260813.md:11-25` | 8 样本被分为 2 类，但无 oracle 差异候选，人工真值为 0/8；聚类数量不证明假阳性下降。 |
| `symcc/docs/DNSPoisonEvidenceContract.md:13-19,72-77,146-180` | `included/excluded/unknown`、正式 `afl_only` baseline、证据摘要和重建命令、publication-audit 门槛。 |
| `symcc/gen_input/include/DST1Transcript.h:20-28,39-58,76-102` | 输入含一条 client query、多条 response、post-check；最多 16 条 response、总长上限 16384 字节；不能称任意长交互建模。 |
| `symcc/dnslab_core/include/dnslab_core/transcript.hpp:11-15` | `TranscriptView` 明确保存 `ClientQuery/ForgedResponses/PostCheckQuery`。 |
| `symcc/dnslab_core/src/main.cpp:1172-1220` | 指纹从缓存记录提取 msg/rrset/negative 是否出现；所读实现填写 BIND9/Unbound 字段，forwarding/retry 保持 null；不能直接称完整内部状态模型或六 resolver 同等状态可观测。 |
| `symcc/tools/dns_diff/triage.py:280-303,323-347` | 候选样本默认仍待人工判定；缺失指纹标记 `partial_fingerprint`，候选不等于漏洞。 |
| `symcc/docs/Fuzzing.txt:19-22,102-110` | SymCC 原有工作流已支持与 AFL 交换输入、选取 promising inputs、回流有趣结果；“把 SymCC 接入 AFL”本身不是本项目新方法。 |

本轮未找到独立 `paper/` 目录或 `.tex/.bib` 相关工作稿；已读取 `symcc/docs/` 中计划、材料状态、结果草稿及相关 RQ 文档。未修改它们。

### 3. 八项最近邻论文/项目

#### R1. ResolverFuzz：最直接的 DNS 缓存差分前作

- **题目**：*ResolverFuzz: Automated Discovery of DNS Resolver Vulnerabilities with Query-Response Fuzzing*。
- **作者**：Qifan Zhang、Xuesong Bai、Xiang Li、Haixin Duan、Qi Li、Zhou Li。
- **Venue / 年份**：USENIX Security 2024；arXiv 首版为 2023，不能据此把正式会议年份写成 2023。
- **一手 URL**：https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-qifan
- **正文 / 官方实现**：https://arxiv.org/html/2310.03202v1 ；https://github.com/ResolverFuzz/ResolverFuzz
- **核验日期**：2026-10-30。
- **已确认机制**：短 query-response 序列的受限状态测试，PCFG 与字节变异联合生成查询和响应；跨实现缓存差分和聚类发现非崩溃缺陷。正文 §4.3 比较缓存 NAME/TYPE/RDATA，将缓存差异数向量交给 Bisecting K-Means，再进行半自动分析。官方摘要报告测试 6 种 DNS 软件、4 种 resolver 模式。
- **与本项目重合**：输入双向性、缓存语义、差分 oracle、降噪和多 resolver 均直接重合。
- **可能差异**：[INFERENCE] 可以研究“覆盖率驱动的单 producer + 有界多 response transcript + 明确后检”相对其 grammar-based blackbox 路线的得失，但必须展示相同预算和相同威胁模型下的增量；不能只比较 query-only 工具后声称超越 DNS 差分现状。

#### R2. ResolFuzz：尤其覆盖重放、后检、启发式及指纹

- **题目**：*ResolFuzz: Differential Fuzzing of DNS Resolvers*。
- **作者 / 机构**：Jonas Bushart、Christian Rossow；CISPA。
- **Venue / 年份**：ESORICS 2023；Springer 章节正式引用年份为 **2024**。会议年份与论文集出版年份分开记录。
- **一手 URL**：https://bushart.org/publications/2023-esorics/resolfuzz.pdf
- **书目信息 / 官方实现**：https://link.springer.com/chapter/10.1007/978-3-031-51476-0_4 ；https://github.com/dns-differential-fuzzing/dns-differential-fuzzing
- **核验日期**：2026-10-30；作者 PDF 正文已读取，会议年份亦由 CISPA 官方出版页核对。
- **已确认机制**：§2.1 要求各 resolver 接收“same logical data”；§2.4 使用一条 client query、多条 AuthNS response，并在 fuzzing 后发送 RD=0 的 cache probing queries；§2.5 协调器统一产生/分发输入并收集多个 resolver 结果；§2.7 对输出排序归一化、过滤已知良性差异、重复运行排除非确定差异，并按 DNS header 与差异字段名构建 fingerprint。还收集各 resolver 的 edge coverage 和缓存信息。
- **与本项目重合**：不仅是“多解析器差分”，还包括统一输入、缓存后检、重复验证、规则过滤、指纹和可复现产物。**不可写“前作只看首次响应、不观察缓存或不验证重放稳定性”。**
- **可能差异**：[INFERENCE] 单 BIND9 producer 与收集多 resolver 覆盖反馈的路线存在实验可检验的成本/发现能力权衡；单 producer 可能更便于控制来源，也可能漏掉 secondary-only 路径。DST1 后检字段是一种表达/执行契约，单凭有该字段不足以区别于现有 cache probing。

#### R3. BGF-DR：对当前计划重合度很高的新近工作

- **题目**：*BGF-DR: bidirectional greybox fuzzing for DNS resolver vulnerability discovery*。
- **作者**：Jie Ying、Jun Li、Ruoxi Chen、Hongxin Su、Tiantian Zhu。
- **Venue / 年份**：*Computers & Security*，2026；作者 Ruoxi Chen 的 ORCID 工作条目标为 2026-03。出版社内容提取未返回完整卷期元数据，本文不填未经一手核对的卷号、页码或 DOI。
- **一手 URL**：https://www.sciencedirect.com/science/article/abs/pii/S0167404825004985
- **作者书目佐证**：https://orcid.org/0000-0003-2626-5448
- **核验日期**：2026-10-30。
- **已确认机制**：出版社可见引言明确写出 branch coverage + state coverage 双反馈、自动收集/插桩状态变量、共同构造和变异查询及匹配响应、跨 resolver 差分、启发式规则过滤、细粒度 fingerprint 聚类。可见实验段列出 BIND 9.18.26、Unbound 1.20.0、Knot Resolver 5.7.1、PowerDNS Recursor 5.0.1。
- **与本项目重合**：几乎覆盖“状态感知双向 fuzzing + 差分 + 启发式 + 指纹降噪”的完整概念链，不能把这组词当作尚未被研究的问题。
- **访问边界 / 可能差异**：完整方法、baseline 表和局限章节未能由开放页面核实；未核验可公开运行的作者 artifact。**不能据此断言其没有单 producer、post-check 或类似重放机制。** [INFERENCE] 本项目若选择可比性和证据可信度为主线，需要具体区分状态表示、运行控制及错误分类，并测量差异；尚不能下“优于 BGF-DR”的结论。

#### R4. SymCC：直接实现基础与混合 fuzzing 基线

- **题目**：*Symbolic execution with SymCC: Don't interpret, compile!*。
- **作者 / 机构**：Sebastian Poeplau、Aurélien Francillon；EURECOM。
- **Venue / 年份**：USENIX Security 2020。
- **一手 URL**：https://www.usenix.org/conference/usenixsecurity20/presentation/poeplau
- **作者复现实验页**：https://s3.eurecom.fr/tools/symbolic_execution/symcc.html
- **核验日期**：2026-10-30。
- **已确认机制**：将 concolic execution 编入 LLVM 生成的程序；与 AFL 协作生成和回流输入。作者实验页明确使用 1 个 AFL master、1 个 AFL secondary、1 个 SymCC 进程；QSYM 对照保持类似设置，论文真实软件实验为 24 小时、30 次重复。
- **与本项目重合**：编译式符号执行、与 AFL 协作和输入回流均属已有基础。其通用基准上的速度/覆盖率结果不能转述为本项目 DNS 实验结果。
- **可能差异 / 基线**：[INFERENCE] 本项目只能把 DNS 字段级局部符号化和语义价值调度视作候选改进。优先对比同 harness 的 `afl_only`、普通 SymCC 回流、语义 gate 回流；QSYM 是可选引擎对照，不应先于这组直接消融。必须计入额外求解进程的 CPU 成本。

#### R5. AFLNet：序列重放及协议状态反馈基线

- **题目**：*AFLNet: A Greybox Fuzzer for Network Protocols*。
- **作者**：Van-Thuan Pham、Marcel Böhme、Abhik Roychoudhury。
- **Venue / 年份**：ICST 2020，Testing Tools Track。
- **一手 URL**：https://github.com/aflnet/aflnet
- **核验日期**：2026-10-30；README 正文及作者提供的 BibTeX 已核对。
- **已确认机制**：由录制消息序列变异/重放，以代码覆盖及服务器响应码推断的状态反馈引导探索。当前官方 README 的 `-P` 支持列表明确包含 `DNS`。
- **与本项目重合**：有状态协议 fuzzing、消息序列与 replay 不新。
- **可能差异 / 基线限制**：[INFERENCE] DNS 缓存状态未必能由响应码区分；其客户端序列路线也不自动等于本项目可控权威响应和跨 resolver 缓存 oracle。但不能据名称声称 AFLNet 不支持 DNS。若使用它作语义 baseline，必须赋予可比的响应控制能力与统一事后 oracle，并披露适配成本。

#### R6. StateAFL：内部状态反馈基线

- **题目**：*StateAFL: Greybox Fuzzing for Stateful Network Servers*。
- **作者**：Roberto Natella。
- **Venue / 年份**：*Empirical Software Engineering*，2022；不是以 arXiv 2021 年替代正式出版年。
- **一手 URL**：https://github.com/stateafl/stateafl
- **正式论文**：https://doi.org/10.1007/s10664-022-10233-3
- **核验日期**：2026-10-30；官方 README 和引用格式已核对。
- **已确认机制**：编译期插桩分配与网络 I/O，运行时快照长寿命内存，以 fuzzy hashing 推断协议状态；同时追求代码和状态覆盖。输入采用 AFLNet 兼容的可重放消息序列。
- **与本项目重合**：状态表示/指纹以及状态感知 fuzzing 已有一般方法。
- **可能差异 / 基线限制**：[INFERENCE] 本项目当前 cache-presence 特征是特定语义观察，不等价于 StateAFL 内部状态推断；不能凭“三个缓存布尔值”声称更全面或更精确。可用它测试通用状态反馈是否足够，但当前未验证其在本项目各 resolver/harness 上可运行。

#### R7. DNS Fuzzing / DNS-Fuzzing：先做名称消歧

- **项目题名 / 机构**：*DNS fuzzing*；CZ.NIC，仓库 `CZ-NIC/dns-fuzzing`。
- **Venue / 年份**：官方项目，不是已核验会议论文；创建/发布年份本轮不作认定。
- **一手 URL**：https://github.com/CZ-NIC/dns-fuzzing
- **核验日期**：2026-10-30。
- **已确认用途**：为 AFL 保存 DNS server fuzzing 的 unique seeds，README 特别提到 Knot DNS packet parser 和按目标分别做 corpus minimization。
- **重合与差异**：可作为包级种子来源；该 README 不是多 resolver 缓存状态差分方法的证据。**“DNS Fuzzing / DNS-Fuzzing”只是模糊名字，不能自动对应一篇新论文。** 若主会话所指另有论文，下一步需要确切作者、题目或 URL。

#### R8. DNS-fuzzer：ResolverFuzz 实际比较过的传统工具

- **项目题名 / 作者标识**：*Dns Fuzzer (cooler name will come later)*；`guyinatuxedo`。
- **Venue / 年份**：官方 GitHub 工具；ResolverFuzz 参考文献将其记作 2019 年资源，但这不是会议发表信息。
- **一手 URL**：https://github.com/guyinatuxedo/dns-fuzzer
- **核验日期**：2026-10-30。
- **已确认机制**：README 提供 DNS 查询 fuzzing、基于进程/连通性的 crash detection 及 crash replay。ResolverFuzz §5.3 将该仓库作为 DNS Fuzzer baseline，并说明测试的是其 crash 发现能力。
- **重合与差异**：与本项目共享 DNS 输入测试及 replay，但其公开接口不提供本项目所需的跨 resolver 缓存语义判定。只胜过这种 query/crash-oriented 工具，不足以支持相对 R1–R3 的创新性。
- **名称警告**：本轮还检索到同名的域名枚举工具，不能混为此 baseline；引用必须保留完整仓库地址。

### 4. 声称边界：哪些已有覆盖，哪些仍要证明

| 想写的声称 | 依据与处理 |
| --- | --- |
| “首次联合变异 DNS 查询和响应” | R1、R2、R3 已覆盖；删除“首次”。 |
| “首次以多 resolver 差分发现非崩溃/cache poisoning 问题” | R1–R3 直接覆盖；不是可用创新点。 |
| “首次对 DNS 状态做启发式过滤与指纹聚类” | R2、R3 直接覆盖，R1 也有缓存向量聚类；不能保留宽泛新颖性声称。 |
| “现有工作不做 cache post-check 或重复重放” | 与 R2 §2.4、§2.7 明文相反；不得这样对比。 |
| “单 producer 消除了状态失配” | [INFERENCE] 统一字节/来源不保证各 resolver 实际消费相同语义，需记录匹配关系、缓存初态、终止条件和执行轨迹；只能作为待验证假设。 |
| “C++ 主体、六 resolver、证据 bundle 本身是研究创新” | 属工程与复现贡献；需要新的测量结论或安全发现，不能独立支撑方法创新。 |
| “SymCC / 高价值 gate 显著提高效率” | 当前本地草稿未观测到稳定变体差异；须重跑在线生成实验，不能由固定队列重复重放推导生成增益。 |
| “fingerprint 降低了假阳性” | 聚类变少只证明压缩；需要人工真值、漏报/误报、审计时间，并与 R1/R2 风格聚类比较。 |
| “发现可利用 cache poisoning” | cache diff、`second_query_hit`、`confirmed_relevant` 或 `publication-audit=ready` 均不是充分条件；须确认非授权记录进入缓存并因果性影响后续答案、说明攻击者能力及排除正常配置差异。 |

### 5. 主会话可直接采用的最小实验论证顺序

下列均为 **[INFERENCE] 规划建议**，未替用户批准新实现范围。

1. **最近邻先于弱基线**：优先 ResolverFuzz、ResolFuzz；BGF-DR 方法必须讨论，若 artifact 不可得明确列为无法运行的比较，不假冒完整复现。包级 DNS-fuzzer 只能作辅助。
2. **先验证可比性，不先追求差异数**：冻结 resolver 版本和模式、共享初始语料、client query 与权威响应匹配规则、缓存初态和重放终止条件。报告总输入、可比较输入、超时/失败/未知分母，以及同一输入重复后的差异稳定性。单 producer 与独立生成/多目标反馈的比较，要同时报告 secondary-only 发现损失。
3. **把后检价值变成因果实验**：固定同一 query-response 输入，比较有/无后检、缓存 dump 与客户端可见答案的判定；区分“缓存内容不同”“协议允许的差异”“后续查询受非授权记录影响”。R2 已有后检，增量不能只写“能后检”。
4. **Hybrid 单独做在线实验**：`afl_only`、普通 SymCC 回流、局部/语义 gate 各自独立生成队列，保持 seeds、核时、超时和重复预算一致；记录 solver 时间、生成/回流/被 AFL 接收的新样本、唯一新边和人工确认 case。固定语料上的 replay ablation 不足以回答生成增益。
5. **降噪按真值而非 cluster 数验收**：与规则过滤、R1 缓存差异向量、R2 输出字段指纹作同数据对照；报告误报、漏报、重复根因压缩和人工审计时间。null/partial 指纹不能静默当完整状态。
6. **安全案例最低证据链**：原始 transcript、配置/版本、before/after cache、后续查询及答案、重复成功率、人工根因、合法攻击者能力、修补前后或其他可信负对照。harness 能注入 forged response 不自动证明现实中的 off-path 攻击可行。

若近期无法得到显著 hybrid 增益，保留“未观测到增益”的结果并将 SymCC 降为可选组件，比包装为新的混合执行技术更可辩护。若最近邻对照、真实 case 和可比性改进均未形成证据，主会话应保留“研究贡献尚未闭合”的规划风险。

## Related Specs

- `.trellis/workflow.md`：本轮保持 planning；持久化研究，不启动实现。
- `.trellis/spec/backend/index.md:15-21` 与 `quality-guidelines.md:19-51`：主要仍为待填模板，未提供 DNS 论文评价专用规范；不得当作成熟方法合同。
- `.trellis/spec/guides/index.md:54-66`：结论需验证，不能仅依赖评审者/代理声称。
- 项目真正可执行的证据口径目前应以 `symcc/docs/DNSPoisonEvidenceContract.md` 及其真实产物为依据；本轮只读取合同，未执行审计。

## Caveats / Not Found

- **最高风险**：ResolverFuzz、ResolFuzz、BGF-DR 对当前方法概念覆盖广；尤其 ResolFuzz 已有 post-test cache probing、重复验证和 fingerprint。未证明“单 producer + DST1 + SymCC”组合具有独立新颖性。
- **访问限制**：BGF-DR 只核验了出版社公开引言、章节片段和作者书目；完整方法/实验 baseline/代码可得性待补。不可把无法访问解释成前作缺少某能力。
- **实验限制**：未构建、运行任何 resolver、SymCC 或外部 baseline；未重跑 publication-audit，未核对历史原始矩阵。文档中的历史 ready 声称和本轮可用证据不能等同。
- **版本限制**：官方项目页仅用于核验功能与书目，未冻结其 commit；真正比较前仍须固定论文版/代码版与配置。本文不推荐用浮动 `master/main` 直接产生终稿数据。
- **检索限制**：默认使用 Keenable `search_web_pages`，需要精确机制时读取官方页面/作者正文；对新近文献做过定向检索，但未做系统综述。搜索结果自动标注的网页发布日期不直接充当论文出版年。
- **范围限制**：只创建本文件；不修改代码、计划、spec、其他报告，不进行任何 git 操作。主会话可据此继续规划，不能据此宣称实验已完成或创新性已获证实。
