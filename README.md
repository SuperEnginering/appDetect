# APK 权限分析工具

## 项目简介
这是一个基于 **jadx** 反编译的 APK 权限分析工具，能够自动提取 APK 中的权限声明、实际调用的权限以及敏感 API（如获取位置、读取联系人等）的使用情况，并生成一份结构化的 Markdown 格式分析报告。报告包含权限统计、权限列表对比、敏感数据收集行为等信息，适用于 Android 应用隐私合规检测和自评估。

## 主要功能
- **APK 基本信息提取**：通过 `aapt` 获取应用名称、包名、版本号、SDK 版本等信息；计算文件哈希（MD5、SHA-1、SHA-256）；提取签名证书信息（DN、MD5）。
- **权限声明分析**：解析 `AndroidManifest.xml` 中声明的所有权限（包括 `<uses-permission>` 和 `<uses-permission-sdk-23>`）。
- **权限调用分析**：扫描反编译后的 Java 源码，检测实际调用权限的代码位置（如 `checkSelfPermission`、`requestPermissions`、`Manifest.permission` 常量引用等），并与声明权限对比，找出未使用或未声明的权限。
- **敏感 API 扫描**：基于 `SensitiveApi.json` 规则文件，检测应用中可能收集个人信息的敏感 API 调用（如获取位置、读取联系人、访问摄像头等），并按数据类型归类，输出调用位置和频率。
- **Markdown 报告生成**：使用模板文件生成可读性强的报告，包含概览统计、权限列表（支持排序和标识个人信息权限）、敏感数据调用列表等。
- **增量分析**：如果已存在反编译输出目录，则跳过反编译步骤，直接进行分析，节省时间。

## 环境要求
- **Java 8 或更高版本**
- **jadx**：反编译工具，需下载并配置路径（本项目使用 jadx-1.4.7）
- **aapt**：Android SDK 自带的资源打包工具，用于提取 APK 基本信息
- 操作系统：Windows（路径分隔符为 `\`，若在 Linux/macOS 下运行需调整路径）

## 安装与配置
### 1. 获取工具
- **jadx**：从 [jadx 官方 GitHub](https://github.com/skylot/jadx/releases) 下载对应版本（本项目默认使用 1.4.7），解压后将 `bin/jadx.bat`（Windows）或 `bin/jadx`（Linux/macOS）放置在 `src/main/resources/tools/jadx-1.4.7/bin/` 目录下（可按需调整路径）。
- **aapt**：可从 Android SDK 的 `build-tools` 目录中获取（如 `$ANDROID_HOME/build-tools/版本/aapt.exe`），复制到 `src/main/resources/tools/aapt/` 目录下。

### 2. 配置文件
在 `Main.java` 中，以下常量需要根据实际情况修改：
```java
private static final String APP_CHINESE_NAME = "czp";           // 应用中文名称（用于生成输出目录和报告文件名）
private static final String JADX_EXECUTABLE = "src\\main\\resources\\tools\\jadx-1.4.7\\bin\\jadx.bat"; // jadx 可执行文件路径
private static final String APK_PATH = Paths.get("src\\main\\resources\\", APP_CHINESE_NAME + ".apk").toString(); // APK 文件路径
private static final String OUTPUT_DIR = Paths.get("src\\main\\resources\\temp\\", APP_CHINESE_NAME + "_output").toString(); // 反编译输出目录
private static final String MD_TEMPLATE_PATH = "src\\main\\resources\\permission_template.md"; // Markdown 模板文件路径
private static final String MD_REPORT_PATH = Paths.get("src\\main\\resources\\temp\\", APP_CHINESE_NAME + "权限分析详情.md").toString(); // 输出报告路径
private static final String AAPT_EXECUTABLE = "src\\main\\resources\\tools\\aapt\\aapt.exe"; // aapt 可执行文件路径
```
- 确保 APK 文件已放置于 `src/main/resources/` 下，且文件名与 `APP_CHINESE_NAME` 一致（如 `czp.apk`）。
- 模板文件 `permission_template.md` 必须存在，可在资源目录中自定义报告样式。

### 3. 敏感 API 规则文件
敏感 API 规则文件位于 `src/main/resources/SensitiveApi.json`，格式如下：
```json
{
  "rules": [
    {
      "type": "位置信息",
      "apis": [
        { "class": "android.location.LocationManager", "method": "getLastKnownLocation", "description": "获取最后已知位置", "permission": "android.permission.ACCESS_FINE_LOCATION" },
        ...
      ]
    },
    ...
  ]
}
```
- `type`：敏感数据类型（如“位置信息”、“联系人”等），将显示在报告中。
- `apis`：该类型下的 API 列表，每个 API 包含 `class`、`method`、`description` 和 `permission` 字段。程序将扫描 Java 源码中调用这些 API 的位置。

## 使用方法
1. **放置 APK 文件**：将待分析的 APK 文件放入 `src/main/resources/` 目录，并重命名为与 `APP_CHINESE_NAME` 一致（如 `czp.apk`）。
2. **运行程序**：在 IDE 中直接运行 `Main` 类的 `main` 方法，或编译打包后执行：
   ```bash
   java -cp your-jar-file.jar com.ruoyi.Main
   ```
3. **查看报告**：程序运行后，将在 `src/main/resources/temp/` 目录下生成反编译源码文件夹和 Markdown 报告文件（如 `czp权限分析详情.md`）。打开报告即可查看分析结果。

### 注意事项
- 首次运行会自动反编译 APK，耗时较长（取决于 APK 大小）。反编译成功后，再次运行将直接使用已有输出目录，快速生成报告。
- 如果反编译过程中出现错误，请检查 jadx 路径是否正确，以及是否具有执行权限。
- 确保 aapt 工具与 APK 的 API 级别兼容，否则可能无法提取基本信息。

## 输出报告解读
生成的 Markdown 报告包含以下主要部分：

### 1. 基本信息概览
- **应用信息**：名称、包名、版本号、大小、SDK 版本等。
- **文件哈希**：MD5、SHA-1、SHA-256。
- **签名证书**：DN 和证书 MD5。
- **分析时间**。

### 2. 权限声明统计
- 总声明权限数、个人信息权限数量及占比、未使用权限数量及占比。
- 声明权限列表：序号、权限名称、权限描述、是否为个人信息权限、是否被实际使用、是否为最小必要权限。

### 3. 权限调用统计
- 总调用权限数、个人信息权限数量。
- 调用权限列表：序号、权限名称、权限描述、是否为个人信息权限、是否已声明、是否为最小必要权限。

### 4. 敏感数据收集行为
- 敏感数据类型、调用位置（类名缩写）、API 调用、行号、调用频率、所需权限等。

## 自定义与扩展
- **修改权限描述**：在 `PermissionAnalyzer` 类的静态初始化块中修改 `PERMISSION_DESC` 映射。
- **调整个人信息权限列表**：修改 `PERSON_INFO_PERM` 集合。
- **调整最小必要权限列表**：修改 `MIN_NECESSARY_PERM` 集合。
- **修改报告模板**：编辑 `permission_template.md`，使用双花括号 `{{变量名}}` 占位，支持循环块（如 `{{#declarePermList}}` ... `{{/declarePermList}}`）。

## 常见问题
### Q: 反编译失败，提示“jadx 不是内部或外部命令”
A: 检查 `JADX_EXECUTABLE` 路径是否正确，jadx 脚本是否有执行权限。Windows 下需确保 `.bat` 文件存在。

### Q: aapt 执行失败，无法提取基本信息
A: 确认 `AAPT_EXECUTABLE` 路径正确，且 aapt 版本支持当前 APK。可尝试在命令行中手动执行 `aapt dump badging your.apk` 测试。

### Q: 敏感 API 检测未生效
A: 确保 `SensitiveApi.json` 文件存在于资源目录，且格式正确。程序启动时会输出“成功加载敏感 API 规则”的提示。

### Q: 报告中的中文显示乱码
A: 确保运行环境的编码为 UTF-8，或在 IDE 中设置文件编码为 UTF-8。

## 许可证
本项目仅供学习和研究使用，请勿用于非法用途。使用第三方工具（jadx、aapt）请遵守其相应许可证。

---

如有问题或建议，欢迎提交 Issue 或联系作者。
