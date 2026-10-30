# 缓存共同语义回归

这些是按实际 BIND dump、Unbound `dump_cache`、SmartDNS `cache ver 1.3`
布局构造的离线 fixture，不是本轮真实 resolver 执行记录。
Python/C++ 均将文件交给生产 parser；SmartDNS 文件为完整二进制缓存。

`cases.tsv` 列为：用例、BIND before、BIND after、secondary 名称、
secondary before、secondary after、预期 `diff_class`。`-` 表示已知空快照。
两种详情输出开关必须得到相同语义结果。

共同投影忽略 TTL 漂移和实现 metadata，但原始快照仍保留它们。
SmartDNS fixture 故意使用 RR TTL=0、cache TTL=600，防止原始 TTL 被替换。
负缓存及仅有名称、无 RDATA 的观测必须不可比较，不能当作无差异。
