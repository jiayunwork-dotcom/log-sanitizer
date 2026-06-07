# log-sanitizer

批量日志文件脱敏与格式标准化命令行工具。

## 功能特性

### 日志格式识别与解析
- **JSON格式**: 每行一个JSON对象，字段不固定
- **Apache/Nginx access log**: Combined Log Format
- **Syslog格式**: RFC 3164和RFC 5424
- **纯文本日志**: 时间戳+级别+消息的常见模式
- **自定义格式**: 用户通过正则表达式定义解析规则，使用命名捕获组
- 解析失败的行标记为"unparseable"保留，并在报告中统计

### 敏感信息检测
- IPv4/IPv6地址
- 邮箱地址
- 手机号（中国大陆11位，支持+86前缀和带横线/空格格式）
- 身份证号（18位，含末位X校验，校验位验证）
- 银行卡号（16-19位数字，Luhn校验）
- URL参数中的Token/Session
- Cookie值
- 自定义正则规则

### 脱敏策略
- **掩码**: 保留前后N位，中间用*替换
- **哈希**: SHA256取前16位hex
- **替换**: 固定占位符替换
- **删除**: 直接移除字段值
- **泛化**: IP保留前两段，邮箱保留域名

### 脱敏一致性
- 同一原始值在整个处理批次中脱敏结果相同
- 支持内存映射（单批次一致）
- 支持SQLite持久化（跨批次一致）
- 原始值使用HMAC-SHA256签名作为key存储

### 格式标准化输出
- 所有日志统一转换为JSON格式
- 标准字段: timestamp(ISO 8601)、level、source、message、extra
- 时间戳统一转换为UTC时区

### Pipeline配置
- YAML文件定义完整处理流水线
- 支持dry-run模式预览脱敏效果

### 流式处理与性能
- 大文件逐行流式读取，内存占用不超过200MB
- 多文件并行处理
- 进度条显示

### 审计报告
- JSON+可读文本两种格式
- 处理行数/解析成功率
- 各类敏感信息检测数量
- 脱敏覆盖率
- 各输入文件统计明细
- 处理耗时/吞吐量

## 安装

```bash
pip install -e .
```

或者

```bash
pip install -r requirements.txt
```

## 快速开始

### 1. 生成示例配置文件
```bash
log-sanitizer init
```

### 2. 验证配置
```bash
log-sanitizer validate -c sanitizer-config.yaml
```

### 3. 预览脱敏效果（dry-run）
```bash
log-sanitizer run -c sanitizer-config.yaml --dry-run
```

### 4. 执行处理
```bash
log-sanitizer run -c sanitizer-config.yaml
```

### 5. 检测文件中的敏感信息
```bash
log-sanitizer detect -i input.log -n 100
```

### 6. 列出所有内置规则
```bash
log-sanitizer list-rules
```

## CLI命令

### `run` - 执行日志处理Pipeline

```bash
log-sanitizer run [OPTIONS]
```

选项:
- `-c, --config PATH: Pipeline配置文件路径(YAML格式) [必需]
- `--dry-run`: 只预览脱敏效果，不实际写入输出文件
- `--overwrite`: 覆盖已存在的输出文件
- `-p, --parallelism INTEGER: 并行处理的文件数
- `-i, --input PATH: 输入文件路径，可多次指定
- `-o, --output PATH: 输出文件路径
- `--no-progress`: 不显示进度条

### `init` - 生成示例配置文件

```bash
log-sanitizer init [OPTIONS]
```

选项:
- `-o, --output PATH: 配置文件输出路径
- `-f, --force`: 强制覆盖已存在文件

### `validate` - 验证配置文件

```bash
log-sanitizer validate [OPTIONS]
```

选项:
- `-c, --config PATH: 配置文件路径 [必需]

### `list-rules` - 列出内置脱敏规则

```bash
log-sanitizer list-rules
```

### `detect` - 检测文件中的敏感信息

```bash
log-sanitizer detect [OPTIONS]
```

选项:
- `-i, --input PATH: 输入文件路径 [必需]
- `-n, --limit INTEGER: 扫描的行数

## 配置文件说明

```yaml
name: "log-processing-pipeline"

inputs:
  paths:
    - "./logs/*.log"
  recursive: true
  encoding: "utf-8"

parser:
  format: "auto"  # auto, json, apache, nginx, syslog, plaintext, custom

filters:
  levels: ["INFO", "WARN", "ERROR"]
  # start_time: "2024-01-01T00:00:00+00:00"
  # end_time: "2024-12-31T23:59:59+00:00"

sanitizers:
  builtin_rules:
    - name: "ipv4"
      enabled: true
      strategy: "generalize"
  custom_rules:
    - name: "custom_ssn"
      pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      strategy: "mask"
  mapping_in_memory: true

output:
  file: "./output/sanitized_logs.jsonl"
  stdout: false
  split_by_day: false

parallelism: 4
dry_run: false

report_file: "./output/audit_report.txt"
report_json: "./output/audit_report.json"
```

## 脱敏策略说明

| 策略 | 说明 | 示例 |
|------|------|------|
| mask | 保留前后N位，中间用*替换 | 138****5678 |
| hash | SHA256取前16位hex | a1b2c3d4e5f6a7b8 |
| replace | 固定占位符替换 | [REDACTED_EMAIL] |
| delete | 直接移除字段值 | (空) |
| generalize | 部分信息隐藏 | 192.168.*.* |

## 默认脱敏策略

| 类型 | 默认策略 | 参数 |
|------|----------|------|
| IP地址 | generalize | - |
| 邮箱 | generalize | - |
| 手机号 | mask | keep_start=3, keep_end=4 |
| 身份证号 | mask | keep_start=4, keep_end=4 |
| 银行卡号 | mask | keep_start=6, keep_end=4 |
| Token/Cookie | replace | - |

## 业务规则

1. **身份证号校验**: 必须验证校验位，纯数字但校验位不通过的不算身份证号

2. **手机号上下文感知**: 
   - 如果11位数字出现在ID/序列号字段中（字段名含id/seq/no等），跳过不脱敏
   - 如果数字前后紧跟其他数字（如时间戳中的一部分），不算手机号

3. **自定义正则编译失败**: 工具启动时报错退出

4. **输出文件已存在**: 默认追加，可通过--overwrite参数切换为覆盖模式

5. **映射表持久化**: 使用SQLite存储，原始值不明文存储

## 项目结构

```
log-sanitizer/
├── log_sanitizer/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py              # CLI入口
│   ├── models.py            # 数据模型
│   ├── utils.py             # 工具函数
│   ├── parser.py            # 日志解析器
│   ├── detector.py          # 敏感信息检测器
│   ├── sanitizer.py         # 脱敏策略引擎
│   ├── mapping_manager.py   # 一致性映射管理器
│   ├── config.py            # 配置解析器
│   ├── processor.py         # 流式处理引擎
│   └── report.py           # 审计报告生成器
├── tests/
│   ├── test_utils.py
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_sanitizer.py
│   ├── test_integration.py
│   └── data/
│       ├── sample_plaintext.log
│       ├── sample_json.log
│       └── sample_apache.log
├── examples/
│   └── sanitizer-config.yaml
├── pyproject.toml
├── requirements.txt
└── README.md
```

## 运行测试

```bash
pytest tests/ -v
```

## 许可证

MIT License
