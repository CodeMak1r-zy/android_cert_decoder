# Android Keystore Decoder

使用 Python + Tkinter 编写的桌面工具，支持在 **macOS** 和 **Windows** 上解析 `.keystore` 文件，获取证书的 SHA1、SHA256、MD5 等指纹信息。

## 功能

- 选择或拖入 `.keystore` 文件
- 输入 **storepass** 解析证书
- 展示 SHA256、SHA1、MD5、Subject、Issuer、有效期
- 一键复制指纹

## 支持的 Keystore 格式

- JKS（Android 传统格式）
- PKCS12（部分 `.keystore` 实际为此格式）
- BKS / UBER

> 读取证书指纹只需 **storepass**，不需要 keypass。

## 本地运行

```bash
pip install -r requirements.txt
python main.py
```

### 依赖说明

- `pyjks` + `cryptography`：纯 Python 解析 keystore，无需安装 Java
- `tkinterdnd2==0.4.2`：文件拖放支持
  - **注意**：请勿升级到 `0.5.x`，该版本在 pyenv / Homebrew Python（Tcl 8.6）下会因二进制不兼容而启动失败

## 使用说明

1. 打开应用
2. 点击「选择 .keystore 文件」或将文件拖入虚线区域
3. 输入 **storepass**
4. 查看解析结果，点击「复制」复制指纹

## 验证示例

可用以下 keystore 验证解析是否正确：

```bash
keytool -list -v -keystore "/path/to/android.keystore" -storepass "Kn8ErI"
```

预期结果：

| 字段   | 值                                                                                                |
| ------ | ------------------------------------------------------------------------------------------------- |
| 格式   | JKS                                                                                               |
| 别名   | `android.keystore`                                                                                |
| SHA1   | `3F:EA:CB:56:67:74:0A:F7:89:4D:15:77:05:DD:D5:52:EC:D0:94:71`                                     |
| SHA256 | `18:9B:E1:16:01:04:09:95:D1:A7:5A:94:C7:EC:EE:9C:92:FD:EE:84:FB:86:56:60:0E:E7:31:33:17:1B:E8:0D` |

## 打包分发

**macOS 无法直接打包出 Windows 的 `.exe`**，必须在 Windows 环境构建，或使用 CI。

### 方式一：Windows 本地打包（推荐）

1. 安装 [Python 3.10+](https://www.python.org/downloads/)，勾选 **Add Python to PATH**
2. 在项目根目录运行：

```bat
build\windows\build.bat
```

3. 产物路径：

```
dist\AndroidKeystoreDecoder\AndroidKeystoreDecoder.exe
```

4. 将 `dist\AndroidKeystoreDecoder` **整个文件夹**打成 zip 分发给同事（不要只发单个 exe，Tkinter 和 tkdnd 依赖同目录下的库文件）

### 方式二：GitHub Actions 自动构建

1. 将项目推送到 GitHub
2. 打开仓库 → **Actions** → **Build Windows** → **Run workflow**
3. 构建完成后在 **Artifacts** 下载 `AndroidKeystoreDecoder-windows` zip

### 方式三：Windows 手动打包

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install pyinstaller
pyinstaller --noconfirm --clean build.spec
```

### macOS 打包（可选）

```bash
pip install pyinstaller
pyinstaller --noconfirm --clean build.spec
```

产物位于 `dist/AndroidKeystoreDecoder/`。

## 给同事验证时的注意事项

- 使用 **storepass**，不是 keypass
- 分发时使用整个 `AndroidKeystoreDecoder` 文件夹，不要只发 exe
- 未签名的 exe 可能触发 Windows SmartScreen，选择「仍要运行」即可
- 若拖入文件后界面无响应，请确认使用的是最新代码（拖放回调已做延迟处理，避免 macOS 卡死）

## 项目结构

```
android_cert_decoder/
├── main.py                 # Tkinter GUI
├── keystore_parser.py      # Keystore 解析逻辑
├── requirements.txt
├── build.spec              # PyInstaller 配置
├── hook-tkinterdnd2.py     # 打包拖放组件
├── build/windows/build.bat # Windows 一键构建脚本
└── .github/workflows/build-windows.yml
```
