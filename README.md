# Google Authenticator Decoder

一个用于解析 Google Authenticator 导出数据并生成二维码的 Python 工具。

## 功能特性

- ✅ 解析 `otpauth-migration://` 格式的导出 URL
- ✅ 自动解码 Base64 和 Protobuf 编码的数据
- ✅ 提取账号信息（名称、发行方、密钥、算法等）
- ✅ 将密钥转换为标准 Base32 格式
- ✅ 生成标准的 `otpauth://` URL（可导入其他 2FA 应用）
- ✅ 为每个账号生成二维码图片
- ✅ 支持 JSON 格式输出
- ✅ 零外部依赖的 Protobuf 解析（核心功能）
- ✅ 支持 TOTP 和 HOTP 类型
- ✅ 支持多种哈希算法（SHA1、SHA256、SHA512、MD5）

## 技术亮点

### 自实现 Protobuf 解析器
本工具完全自己实现了 Protobuf wire format 解析，无需依赖 `protobuf` 库，避免了版本兼容性问题。核心解析功能只使用 Python 标准库。

### 轻量依赖
- **核心功能**：零外部依赖
- **二维码生成**：仅需 `qrcode[pil]`

## 安装

### 前置要求

- Python >= 3.12
- uv（推荐的 Python 包管理器）

### 安装 uv

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 克隆项目

```bash
git clone <repository-url>
cd google-auth-decoder
```

### 安装依赖

```bash
uv sync
```

## 使用方法

### 获取导出 URL

1. 打开 Google Authenticator 应用
2. 点击右上角的三点菜单
3. 选择"导出账号"
4. 选择要导出的账号
5. 使用二维码扫描工具获取 `otpauth-migration://` 开头的 URL

### 基础用法

```bash
# 解析并显示账号信息
uv run ga-decoder "otpauth-migration://offline?data=..."

# 或使用脚本文件
uv run ga_decoder.py "otpauth-migration://offline?data=..."
```

### 生成二维码

```bash
# 生成二维码到默认目录 (./qrcodes)
uv run ga-decoder --qr "otpauth-migration://offline?data=..."

# 指定自定义输出目录
uv run ga-decoder --qr --qr-dir ./my-qrcodes "otpauth-migration://offline?data=..."
```

### JSON 格式输出

```bash
# 输出 JSON 格式
uv run ga-decoder --json "otpauth-migration://offline?data=..."

# JSON 格式 + 生成二维码
uv run ga-decoder --qr --json "otpauth-migration://offline?data=..."
```

## 命令行选项

```
usage: ga-decoder [-h] [--json] [--qr] [--qr-dir QR_DIR] url

positional arguments:
  url              Google Authenticator 导出的 URL

options:
  -h, --help       显示帮助信息
  --json           以 JSON 格式输出结果
  --qr             为每个账号生成二维码图片
  --qr-dir QR_DIR  指定二维码保存目录 (默认: ./qrcodes)
```

## 输出示例

### 标准输出

```
================================================================================
Found 2 account(s):
================================================================================

Account #1
  Name:      user@example.com
  Issuer:    Google
  Type:      TOTP
  Algorithm: SHA1
  Digits:    6
  Secret:    JBSWY3DPEHPK3PXP
  URL:       otpauth://totp/Google%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google

Account #2
  Name:      developer@github.com
  Issuer:    GitHub
  Type:      TOTP
  Algorithm: SHA1
  Digits:    6
  Secret:    HXDMVJECJJWSRB3H
  URL:       otpauth://totp/GitHub%3Adeveloper%40github.com?secret=HXDMVJECJJWSRB3H&issuer=GitHub
```

### JSON 输出

```json
[
  {
    "name": "user@example.com",
    "issuer": "Google",
    "secret_base32": "JBSWY3DPEHPK3PXP",
    "algorithm": "SHA1",
    "digits": 6,
    "type": "totp",
    "counter": null,
    "otpauth_url": "otpauth://totp/Google%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google",
    "qr_code_path": "qrcodes/Google_user_example.com.png"
  }
]
```

### 二维码生成

使用 `--qr` 选项时，会为每个账号生成二维码图片：

```
Generated 2 QR code(s) in: /path/to/qrcodes

Account #1
  ...
  QR Code:   qrcodes/Google_user_example.com.png
```

生成的二维码可以：
- 用其他 2FA 应用扫描导入
- 保存备份
- 打印存档

## 文件命名规则

二维码文件名格式：`发行方_账号名.png`

- 自动清理非法字符（`:`, `@`, `/`, 空格等）
- 替换为下划线 `_`
- 限制文件名长度为 100 字符
- 自动处理重名（添加序号后缀）

示例：
- `Google:user@example.com` → `Google_user_example.com.png`
- `GitHub:developer@test.com` → `GitHub_developer_test.com.png`

## 技术细节

### Protobuf 结构

本工具解析的 Google Authenticator 导出数据遵循以下 Protobuf 结构：

```protobuf
message MigrationPayload {
  message OTPParameters {
    bytes secret = 1;
    string name = 2;
    string issuer = 3;
    enum Algorithm { ALGORITHM_UNSPECIFIED = 0; SHA1 = 1; SHA256 = 2; SHA512 = 3; MD5 = 4; }
    Algorithm algorithm = 4;
    enum Digits { DIGITS_UNSPECIFIED = 0; SIX = 1; EIGHT = 2; }
    Digits digits = 5;
    enum OTPType { OTP_TYPE_UNSPECIFIED = 0; HOTP = 1; TOTP = 2; }
    OTPType type = 6;
    int64 counter = 7;
  }
  repeated OTPParameters otp_parameters = 1;
  int32 version = 2;
  int32 batch_size = 3;
  int32 batch_index = 4;
  int32 batch_id = 5;
}
```

### Wire Format 解析

工具实现了完整的 Protobuf wire format 解析器，支持：
- Varint 编码（变长整数）
- Length-delimited 字段（字符串、字节）
- Fixed32/Fixed64（固定长度字段）
- 嵌套消息解析

### Base32 编码

工具将原始密钥字节转换为标准 Base32 编码，符合 [RFC 4648](https://tools.ietf.org/html/rfc4648) 规范，确保与所有标准 TOTP/HOTP 应用兼容。

## 安全注意事项

⚠️ **重要提示**：

1. **导出的数据包含敏感信息**
   - URL 中包含未加密的密钥
   - 请勿分享导出 URL 或二维码
   - 使用后建议删除临时文件

2. **二维码安全**
   - 生成的二维码可直接导入 2FA 账号
   - 请妥善保管二维码图片
   - 建议加密存储或打印后销毁数字副本

3. **备份建议**
   - 将二维码保存到安全位置
   - 考虑离线存储（打印、加密 U 盘等）
   - 定期验证备份的有效性

## 故障排除

### 命令未找到错误

```bash
# 错误：uv run ga_decoder
error: Failed to spawn: `ga_decoder`

# 正确：使用连字符
uv run ga-decoder --qr "..."

# 或：使用完整文件名
uv run ga_decoder.py --qr "..."
```

### URL 解析失败

确保 URL 格式正确：
- 必须以 `otpauth-migration://` 开头
- 包含 `data=` 参数
- URL 需要用引号包裹

```bash
# 正确
uv run ga-decoder "otpauth-migration://offline?data=Ck..."

# 错误（缺少引号，shell 可能截断 URL）
uv run ga-decoder otpauth-migration://offline?data=Ck...
```

### Python 版本不兼容

本工具要求 Python >= 3.12。检查版本：

```bash
python --version
uv python list
```

## 开发

### 项目结构

```
google-auth-decoder/
├── ga_decoder.py      # 主脚本
├── pyproject.toml     # 项目配置
├── README.md          # 本文档
├── .gitignore         # Git 忽略配置
└── qrcodes/           # 默认二维码输出目录（生成时创建）
```

### 运行测试

```bash
# 安装开发依赖
uv sync

# 查看帮助
uv run ga-decoder --help

# 使用示例数据测试
uv run ga-decoder "otpauth-migration://offline?data=..."
```

## 依赖项

- **核心功能**：无外部依赖（仅 Python 标准库）
- **二维码生成**：
  - `qrcode >= 7.4.2`
  - `pillow >= 12.0.0`（通过 `qrcode[pil]` 自动安装）

## 许可证

本项目仅供学习和个人使用。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 相关资源

- [Google Authenticator](https://github.com/google/google-authenticator)
- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - HOTP](https://tools.ietf.org/html/rfc4226)
- [RFC 4648 - Base32](https://tools.ietf.org/html/rfc4648)
- [Protocol Buffers](https://developers.google.com/protocol-buffers)

## 常见问题

### Q: 生成的二维码可以导入哪些应用？

A: 所有支持标准 TOTP/HOTP 协议的应用，包括：
- Microsoft Authenticator
- Authy
- 1Password
- Bitwarden
- LastPass Authenticator
- 等等

### Q: 原始的 Google Authenticator 账号会被删除吗？

A: 不会。本工具只是读取导出数据，不会修改或删除原始账号。

### Q: 可以批量导出所有账号吗？

A: 可以。Google Authenticator 支持一次导出多个账号，本工具会自动解析所有账号并为每个生成独立的二维码。

### Q: 支持哪些操作系统？

A: 支持所有运行 Python 3.12+ 的系统：
- macOS
- Linux
- Windows

### Q: 如何验证导出的数据是否正确？

A: 使用生成的二维码在其他 2FA 应用中导入，验证生成的验证码是否与原 Google Authenticator 一致。

---

**注意**：本工具仅用于合法的个人数据备份和迁移用途。请遵守相关服务的使用条款。
