# 安全策略

## 支持版本

| 版本 | 支持 |
|------|------|
| 1.0.x | ✅ |

## 报告漏洞

请不要在公开 Issue 中描述可被利用的细节。请使用 GitHub 的
[私下安全报告](https://docs.github.com/zh/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
功能提交，或通过仓库主页列出的维护者联系方式联系。

我们会在 7 天内确认收到，并在修复发布前对细节保密。

## 威胁模型说明

本工具是**纯离线的协议结构分析器**，设计中不涉及：

- 网络监听、抓包或主动探测（不做任何网络 I/O）；
- 执行输入流中的任何字节（输入始终按纯数据处理）。

使用 MCP 传输时，输入由客户端提供；对来自不可信来源的字节流，
本工具按"只读分析"处理，不会回写、不会外传数据。
