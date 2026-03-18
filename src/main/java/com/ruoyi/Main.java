package com.ruoyi;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.security.cert.X509Certificate;

/**
 * APK 权限分析工具 - 生成 Markdown 报告
 * 依赖 jadx 反编译 APK，解析权限调用和敏感 API 调用，输出 Markdown 格式分析报告
 */
public class Main {
    // 1. 统一常量修饰符：private static final（常量规范）
    // 2. 中文名称常量私有化，避免外部随意修改
    private static final String APP_CHINESE_NAME = "weixin";

    // 工具路径配置（统一规范 + 路径拼接优化）
    private static final String JADX_EXECUTABLE = "src\\main\\resources\\tools\\jadx-1.4.7\\bin\\jadx.bat";
    // 优化：用 Paths 拼接路径，避免硬编码分隔符，同时保证编译期常量特性
    private static final String APK_PATH = Paths.get("src\\main\\resources\\", APP_CHINESE_NAME + ".apk").toString();
    private static final String OUTPUT_DIR = Paths.get("src\\main\\resources\\temp\\", APP_CHINESE_NAME + "_output").toString();
    private static final String MD_TEMPLATE_PATH = "src\\main\\resources\\permission_template.md";
    private static final String MD_REPORT_PATH = Paths.get("src\\main\\resources\\temp\\", APP_CHINESE_NAME + "权限分析详情.md").toString();
    private static final String AAPT_EXECUTABLE = "src\\main\\resources\\tools\\aapt\\aapt.exe";



    public static void main(String[] args) throws IOException {
        File apkFile = new File(APK_PATH);
        File outDir = new File(OUTPUT_DIR);


        // 提取 APK 基本信息
        System.out.println("提取 APK 基本信息");
        Map<String, String> basicInfo = ApkInfoExtractor.getBasicInfo(APK_PATH, AAPT_EXECUTABLE);


        if (outDir.exists() && outDir.isDirectory()) {
            System.out.println("检测到已存在的反编译输出目录，跳过反编译步骤，直接进行权限分析...");
            PermissionAnalyzer.analyze(outDir.getAbsolutePath(), MD_REPORT_PATH, APP_CHINESE_NAME, basicInfo);
            System.out.println("Markdown 权限分析报告生成：" + MD_REPORT_PATH);
            return;
        }

        // 构建 jadx 反编译命令
        ProcessBuilder pb = new ProcessBuilder(
                JADX_EXECUTABLE,
                "-d", outDir.getAbsolutePath(),
                "--deobf",
                "--show-bad-code",
                "-j", "4",
                apkFile.getAbsolutePath()
        );
        pb.redirectErrorStream(true);

        try {
            System.out.println("开始反编译 APK...");
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                System.out.println("反编译成功，开始分析权限...");
                PermissionAnalyzer.analyze(outDir.getAbsolutePath(), MD_REPORT_PATH, APP_CHINESE_NAME,basicInfo);
                System.out.println("Markdown 权限分析报告生成：" + MD_REPORT_PATH);
            } else {
                System.err.println("反编译失败，退出码：" + exitCode);
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * 权限分析器
     */
    public static class PermissionAnalyzer {
        static class GroupedSensitiveCall {
            String dataType;
            String className;
            String apiClass;
            String apiMethod;
            int frequency;
            Set<Integer> lineNumbers = new TreeSet<>();
            String requiredPermission;  // 取第一条记录的权限（假设相同）
        }

        static class MergedSensitiveCall {
            String className;
            String apiClass;
            String apiMethod;
            Set<String> dataTypes = new TreeSet<>();    // 存储多种数据类型，自动排序
            Set<Integer> lineNumbers = new TreeSet<>(); // 存储行号
        }

        /**
         * 类名缩写：保留包名最后两段（如 com.huluxia.utils.C7205r -> utils.C7205r）
         */
        private static String abbreviateClassName(String fullName) {
            String[] parts = fullName.split("\\.");
            if (parts.length <= 2) return fullName;
            // 取最后两段
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }

        /**
         * 行号集合转字符串，如果超过5个则省略中间
         */
        private static String joinLineNumbers(Set<Integer> lineNumbers) {
            if (lineNumbers == null || lineNumbers.isEmpty()) return "";
            List<Integer> list = new ArrayList<>(lineNumbers);
            if (list.size() <= 5) {
                return list.toString().replace("[", "").replace("]", "");
            } else {
                // 显示前两个和后两个
                return list.get(0) + ", " + list.get(1) + ", ... , " + list.get(list.size() - 2) + ", " + list.get(list.size() - 1);
            }
        }
        // 常见危险权限列表（用于判断是否可收集个人信息，此处保留但不直接用于 Markdown）
        private static final Set<String> DANGEROUS_PERMISSIONS = new HashSet<>(Arrays.asList(
                "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
                "android.permission.CAMERA", "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS",
                "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.RECORD_AUDIO", "android.permission.READ_PHONE_STATE",
                "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG", "android.permission.ADD_VOICEMAIL",
                "android.permission.USE_SIP", "android.permission.PROCESS_OUTGOING_CALLS",
                "android.permission.BODY_SENSORS", "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
                "android.permission.RECEIVE_WAP_PUSH", "android.permission.RECEIVE_MMS",
                "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.SYSTEM_ALERT_WINDOW"
        ));

        // 权限含义映射
        private static final Map<String, String> PERMISSION_DESC = new HashMap<>();

        // 可收集个人信息的权限列表
        private static final Set<String> PERSON_INFO_PERM = new HashSet<>();

        // 最小必要权限列表
        private static final Set<String> MIN_NECESSARY_PERM = new HashSet<>();

        // 敏感 API 规则列表
        private static List<SensitiveRule> sensitiveRules = null;

        // 敏感 API 规则文件路径（资源目录）
        private static final String SENSITIVE_RULES_PATH = "/SensitiveApi.json";

        static {
            // 权限含义初始化（参考 Android 官方文档及厂商自定义说明）
            PERMISSION_DESC.put("android.permission.ACCESS_WIFI_STATE", "查看WLAN状态");
            PERMISSION_DESC.put("android.permission.CAMERA", "访问相机");
            PERMISSION_DESC.put("android.permission.READ_EXTERNAL_STORAGE", "读取SD卡上的内容");
            PERMISSION_DESC.put("android.permission.WRITE_EXTERNAL_STORAGE", "修改/删除SD卡中的内容");
            PERMISSION_DESC.put("android.permission.READ_PHONE_STATE", "读取手机状态和身份");
            PERMISSION_DESC.put("android.permission.ACCESS_BACKGROUND_LOCATION", "支持后台访问位置");
            PERMISSION_DESC.put("android.permission.CHANGE_WIFI_STATE", "更改WLAN状态");
            PERMISSION_DESC.put("android.permission.ACCESS_COARSE_LOCATION", "访问大概位置");
            PERMISSION_DESC.put("android.permission.ACCESS_FINE_LOCATION", "访问精确位置");
            PERMISSION_DESC.put("android.permission.SYSTEM_ALERT_WINDOW", "显示系统级警报");
            PERMISSION_DESC.put("android.permission.READ_APP_BADGE", "读取应用角标（通用）");
            PERMISSION_DESC.put("android.permission.WAKE_LOCK", "防止手机休眠");
            PERMISSION_DESC.put("com.htc.launcher.permission.READ_SETTINGS", "读取HTC桌面设置");
            PERMISSION_DESC.put("com.oppo.launcher.permission.WRITE_SETTINGS", "写入OPPO桌面设置");
            PERMISSION_DESC.put("com.htc.launcher.permission.UPDATE_SHORTCUT", "更新HTC桌面快捷方式");
            PERMISSION_DESC.put("com.sec.android.provider.badge.permission.READ", "读取三星角标");
            PERMISSION_DESC.put("android.permission.CHANGE_NETWORK_STATE", "更改网络连接性");
            PERMISSION_DESC.put("android.permission.WRITE_SETTINGS", "修改全局系统设置");
            PERMISSION_DESC.put("com.huawei.android.launcher.permission.CHANGE_BADGE", "修改华为桌面角标");
            PERMISSION_DESC.put("com.sec.android.provider.badge.permission.WRITE", "写入三星角标");
            PERMISSION_DESC.put("android.permission.RECEIVE_USER_PRESENT", "用户解锁后唤醒设备");
            PERMISSION_DESC.put("com.anddoes.launcher.permission.UPDATE_COUNT", "更新启动器角标计数");
            PERMISSION_DESC.put("com.huawei.android.launcher.permission.READ_SETTINGS", "读取华为桌面设置");
            PERMISSION_DESC.put("com.sonyericsson.home.permission.BROADCAST_BADGE", "广播角标（索尼）");
            PERMISSION_DESC.put("android.permission.FOREGROUND_SERVICE", "允许使用前端服务");
            PERMISSION_DESC.put("android.permission.REQUEST_INSTALL_PACKAGES", "允许程序安装文件");
            PERMISSION_DESC.put("com.fingard.ats.app.permission.JPUSH_MESSAGE", "极光推送消息");
            PERMISSION_DESC.put("com.huawei.android.launcher.permission.WRITE_SETTINGS", "写入华为桌面设置");
            PERMISSION_DESC.put("com.sonymobile.home.permission.PROVIDER_INSERT_BADGE", "插入角标（索尼移动）");
            PERMISSION_DESC.put("android.permission.GET_TASKS", "检索当前运行的应用程序（已废弃）");
            PERMISSION_DESC.put("com.fingard.ats.app.permission.MIPUSH_RECEIVE", "小米推送接收");
            PERMISSION_DESC.put("com.huawei.appmarket.service.commondata.permission.GET_COMMON_DATA", "获取华为应用市场通用数据");
            PERMISSION_DESC.put("android.permission.ACCESS_LOCATION_EXTRA_COMMANDS", "访问额外的位置信息提供程序命令");
            PERMISSION_DESC.put("android.permission.INTERNET", "访问网络");
            PERMISSION_DESC.put("android.permission.USE_FINGERPRINT", "允许使用指纹");
            PERMISSION_DESC.put("com.fingard.ats.app.permission.PROCESS_PUSH_MSG", "处理推送消息");
            PERMISSION_DESC.put("com.majeur.launcher.permission.UPDATE_BADGE", "更新角标（Majeur）");
            PERMISSION_DESC.put("android.permission.ACCESS_NETWORK_STATE", "查看网络状态");
            PERMISSION_DESC.put("android.permission.MOUNT_UNMOUNT_FILESYSTEMS", "装载和卸载文件系统");
            PERMISSION_DESC.put("android.permission.VIBRATE", "控制振动器");
            PERMISSION_DESC.put("com.fingard.ats.app.permission.PUSH_PROVIDER", "推送提供程序");
            PERMISSION_DESC.put("com.oppo.launcher.permission.READ_SETTINGS", "读取OPPO桌面设置");

            // 可收集个人信息权限初始化（包含所有危险权限及部分特殊权限）
            PERSON_INFO_PERM.add("android.permission.CAMERA");
            PERSON_INFO_PERM.add("android.permission.READ_EXTERNAL_STORAGE");
            PERSON_INFO_PERM.add("android.permission.WRITE_EXTERNAL_STORAGE");
            PERSON_INFO_PERM.add("android.permission.READ_PHONE_STATE");
            PERSON_INFO_PERM.add("android.permission.ACCESS_BACKGROUND_LOCATION");
            PERSON_INFO_PERM.add("android.permission.ACCESS_COARSE_LOCATION");
            PERSON_INFO_PERM.add("android.permission.ACCESS_FINE_LOCATION");
            PERSON_INFO_PERM.add("android.permission.SYSTEM_ALERT_WINDOW");
            PERSON_INFO_PERM.add("android.permission.RECORD_AUDIO");           // 麦克风
            PERSON_INFO_PERM.add("android.permission.READ_CONTACTS");          // 读取联系人
            PERSON_INFO_PERM.add("android.permission.WRITE_CONTACTS");         // 写入联系人
            PERSON_INFO_PERM.add("android.permission.READ_CALENDAR");          // 读取日历
            PERSON_INFO_PERM.add("android.permission.WRITE_CALENDAR");         // 写入日历
            PERSON_INFO_PERM.add("android.permission.BODY_SENSORS");           // 身体传感器
            PERSON_INFO_PERM.add("android.permission.READ_SMS");               // 读取短信
            PERSON_INFO_PERM.add("android.permission.SEND_SMS");               // 发送短信
            PERSON_INFO_PERM.add("android.permission.RECEIVE_SMS");            // 接收短信
            PERSON_INFO_PERM.add("android.permission.USE_FINGERPRINT");        // 指纹（生物识别）
            // Android 13+ 新增的通知权限也涉及用户隐私，可考虑加入
            PERSON_INFO_PERM.add("android.permission.POST_NOTIFICATIONS");     // 发送通知（需用户授权）

            // 最小必要权限初始化（通用基础权限，大多数App实现核心功能所必需）
            MIN_NECESSARY_PERM.add("android.permission.INTERNET");
            MIN_NECESSARY_PERM.add("android.permission.ACCESS_NETWORK_STATE");

            // 加载敏感 API 规则
            try (InputStream is = PermissionAnalyzer.class.getResourceAsStream(SENSITIVE_RULES_PATH)) {
                if (is == null) {
                    System.err.println("警告：未找到敏感 API 规则文件 " + SENSITIVE_RULES_PATH + "，敏感数据检测功能将不可用。");
                } else {
                    // 兼容 Java 8 的读取方式：使用 ByteArrayOutputStream
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        baos.write(buffer, 0, len);
                    }
                    String json = baos.toString(StandardCharsets.UTF_8.name());

                    Gson gson = new Gson();
                    Type type = new TypeToken<Map<String, List<SensitiveRule>>>() {}.getType();
                    Map<String, List<SensitiveRule>> root = gson.fromJson(json, type);
                    List<SensitiveRule> allRules = root.get("rules");

                    // 过滤掉无效的 API
                    if (allRules != null) {
                        for (SensitiveRule rule : allRules) {
                            List<ApiInfo> validApis = new ArrayList<>();
                            for (ApiInfo api : rule.apis) {
                                if (api.clazz == null || api.clazz.trim().isEmpty() || api.method == null || api.method.trim().isEmpty()) {
                                    System.err.println("警告: 敏感数据类型 '" + rule.type + "' 中的 API 缺少 class 或 method 字段，已跳过该API");
                                    continue;
                                }
                                validApis.add(api);
                            }
                            rule.apis = validApis;
                        }
                        // 移除没有有效 API 的规则（可选）
                        sensitiveRules = new ArrayList<>();
                        for (SensitiveRule rule : allRules) {
                            if (!rule.apis.isEmpty()) {
                                sensitiveRules.add(rule);
                            }
                        }
                        System.out.println("成功加载敏感 API 规则，共 " + sensitiveRules.size() + " 类敏感数据类型。");
                    }
                }
            } catch (IOException e) {
                System.err.println("加载敏感 API 规则失败: " + e.getMessage());
            }
        }

        /**
         * 核心分析方法
         *
         * @param srcDir       反编译源码目录
         * @param mdReportPath Markdown报告输出路径
         */
        public static void analyze(String srcDir, String mdReportPath, String appChineseName, Map<String, String> basicInfo) throws IOException {
            // 1. 解析源码中的权限调用（去重）
            Set<String> usedPermissions = new TreeSet<>();
            List<PermissionCall> permCalls = analyzeDirectory(srcDir);
            for (PermissionCall call : permCalls) {
                usedPermissions.add(call.permission);
            }

            // 2. 解析Manifest中的声明权限
            File manifestFile = findManifestFile(srcDir);
            Set<String> declaredPermissions = new TreeSet<>();
            if (manifestFile != null && manifestFile.exists()) {
                declaredPermissions = parseManifestPermissions(manifestFile);
                System.out.println("找到 Manifest 文件，声明了 " + declaredPermissions.size() + " 个权限");
            } else {
                System.out.println("警告：未找到 AndroidManifest.xml，将跳过声明对比");
            }

            // 3. 扫描敏感 API 调用
            List<SensitiveDataCall> sensitiveCalls = new ArrayList<>();
            if (sensitiveRules != null) {
                sensitiveCalls = scanSensitiveApis(srcDir);
                System.out.println("敏感 API 扫描完成，发现 " + sensitiveCalls.size() + " 处调用");
            } else {
                System.out.println("敏感 API 规则未加载，跳过敏感数据检测。");
            }

            // 4. 生成Markdown报告
            generateMarkdownReport(declaredPermissions, usedPermissions, sensitiveCalls, mdReportPath, appChineseName, basicInfo);
        }

        /**
         * 生成Markdown格式权限分析报告（包含敏感数据收集行为）
         */
        private static void generateMarkdownReport(Set<String> declaredPermissions,
                                                   Set<String> usedPermissions,
                                                   List<SensitiveDataCall> sensitiveCalls,
                                                   String mdReportPath,
                                                   String appChineseName,
                                                   Map<String, String> basicInfo) throws IOException {
            // ----- 准备统计数据 -----
            int declareTotal = declaredPermissions.size();
            long declarePersonInfoCount = declaredPermissions.stream().filter(PERSON_INFO_PERM::contains).count();
            long declareUnusedCount = declaredPermissions.stream().filter(p -> !usedPermissions.contains(p)).count();
            String declarePersonInfoRate = declareTotal == 0 ? "0.00" : String.format("%.2f", (double) declarePersonInfoCount / declareTotal * 100);
            String declareUnusedRate = declareTotal == 0 ? "0.00" : String.format("%.2f", (double) declareUnusedCount / declareTotal * 100);

            int usedTotal = usedPermissions.size();
            long usedPersonInfoCount = usedPermissions.stream().filter(PERSON_INFO_PERM::contains).count();

            // 声明权限列表数据
            List<Map<String, String>> declarePermList = new ArrayList<>();
            int serial = 1;
            for (String perm : declaredPermissions) {
                Map<String, String> map = new LinkedHashMap<>();
                map.put("serial", String.valueOf(serial++));
                map.put("permName", perm);
                map.put("permDesc", PERMISSION_DESC.getOrDefault(perm, "未知权限"));
                map.put("isPersonInfo", PERSON_INFO_PERM.contains(perm) ? "是" : "否");
                map.put("isUsed", usedPermissions.contains(perm) ? "是" : "否");
                map.put("isMinNecessary", MIN_NECESSARY_PERM.contains(perm) ? "是" : "否");
                declarePermList.add(map);
            }

            // 使用权限列表数据
            List<Map<String, String>> usedPermList = new ArrayList<>();
            serial = 1;
            for (String perm : usedPermissions) {
                Map<String, String> map = new LinkedHashMap<>();
                map.put("serial", String.valueOf(serial++));
                map.put("permName", perm);
                map.put("permDesc", PERMISSION_DESC.getOrDefault(perm, "未知权限"));
                map.put("isPersonInfo", PERSON_INFO_PERM.contains(perm) ? "是" : "否");
                map.put("isDeclared", declaredPermissions.contains(perm) ? "是" : "否");
                map.put("isMinNecessary", MIN_NECESSARY_PERM.contains(perm) ? "是" : "否");
                usedPermList.add(map);
            }

            // 敏感数据调用列表（按类名+API类名+API方法名合并，并收集数据类型）
            List<Map<String, String>> sensitiveDataList = new ArrayList<>();
            if (sensitiveCalls != null && !sensitiveCalls.isEmpty()) {
                // 1. 合并相同代码位置的调用
                Map<String, MergedSensitiveCall> mergedMap = new LinkedHashMap<>();
                for (SensitiveDataCall call : sensitiveCalls) {
                    String key = call.className + "|" + call.apiClass + "|" + call.apiMethod;
                    MergedSensitiveCall m = mergedMap.get(key);
                    if (m == null) {
                        m = new MergedSensitiveCall();
                        m.className = call.className;
                        m.apiClass = call.apiClass;
                        m.apiMethod = call.apiMethod;
                        mergedMap.put(key, m);
                    }
                    m.dataTypes.add(call.dataType);
                    m.lineNumbers.add(call.lineNumber);
                }

                // 2. 生成报告行数据
                int serial1 = 1;
                for (MergedSensitiveCall m : mergedMap.values()) {
                    Map<String, String> map = new LinkedHashMap<>();
                    map.put("serial", String.valueOf(serial1++));

                    // 合并数据类型，用逗号分隔
                    String combinedDataType = String.join(", ", m.dataTypes);
                    map.put("dataType", combinedDataType);

                    // 类名缩写（保留最后两段）
                    map.put("shortClass", abbreviateClassName(m.className));

                    // API调用
                    map.put("apiCall", m.apiClass + "." + m.apiMethod);

                    // 行号（合并显示）
                    map.put("lineNumbers", joinLineNumbers(m.lineNumbers));

                    // 调用频率 = 行号数量（或 m.lineNumbers.size()）
                    map.put("frequency", String.valueOf(m.lineNumbers.size()));

                    // 所需权限（因合并后可能有多种，可根据需要留空或设为“多种”）
                    map.put("requiredPermission", "多种");

                    // 备注（留空）
                    map.put("remark", "");

                    sensitiveDataList.add(map);
                }
            }

            // 读取模板
            List<String> templateLines = Files.readAllLines(Paths.get(MD_TEMPLATE_PATH), StandardCharsets.UTF_8);
            List<String> outputLines = new ArrayList<>();

            // 第一步：先替换所有简单统计变量 + 基本信息变量
            for (int i = 0; i < templateLines.size(); i++) {
                String line = templateLines.get(i);
                line = replaceSimpleVariables(line,
                        declareTotal, declarePersonInfoCount, declarePersonInfoRate,
                        declareUnusedCount, declareUnusedRate,
                        usedTotal, usedPersonInfoCount,
                        appChineseName);
                // 额外替换基本信息字段
                if (basicInfo != null) {
                    for (Map.Entry<String, String> entry : basicInfo.entrySet()) {
                        line = line.replace("{{" + entry.getKey() + "}}", entry.getValue());
                    }
                }
                templateLines.set(i, line);
            }

            // 第二步：处理循环块
            int i = 0;
            while (i < templateLines.size()) {
                String line = templateLines.get(i);

                // 处理声明权限循环开始（行中包含 {{#declarePermList}}）
                if (line.contains("{{#declarePermList}}")) {
                    i = processLoopBlock(templateLines, i, "{{/declarePermList}}", declarePermList, outputLines);
                    continue;
                }

                // 处理使用权限循环开始（行中包含 {{#usedPermList}}）
                if (line.contains("{{#usedPermList}}")) {
                    i = processLoopBlock(templateLines, i, "{{/usedPermList}}", usedPermList, outputLines);
                    continue;
                }

                // 处理敏感数据循环开始（行中包含 {{#sensitiveDataList}}）
                if (line.contains("{{#sensitiveDataList}}")) {
                    i = processLoopBlock(templateLines, i, "{{/sensitiveDataList}}", sensitiveDataList, outputLines);
                    continue;
                }

                // 普通行（不包含循环标记）直接加入输出
                outputLines.add(line);
                i++;
            }

            // 写入最终Markdown文件
            Files.write(Paths.get(mdReportPath), outputLines, StandardCharsets.UTF_8);
        }

        /**
         * 处理循环块的通用方法
         * @param lines 模板所有行
         * @param startIdx 循环开始行索引
         * @param endTag 结束标记
         * @param dataList 数据列表（每个元素是一个Map）
         * @param outputLines 输出行列表
         * @return 循环结束后的下一行索引
         */
        private static int processLoopBlock(List<String> lines, int startIdx, String endTag,
                                            List<Map<String, String>> dataList, List<String> outputLines) {
            int endIdx = findEndTag(lines, startIdx, endTag);
            if (endIdx == -1) {
                throw new RuntimeException("模板格式错误：未找到结束标记 " + endTag);
            }

            // 提取循环体模板行（从开始行的下一行到结束行的上一行）
            List<String> blockLines = new ArrayList<>();
            for (int j = startIdx + 1; j < endIdx; j++) {
                blockLines.add(lines.get(j));
            }

            // 为每个数据项生成一组行
            for (Map<String, String> item : dataList) {
                for (String blockLine : blockLines) {
                    String processed = replaceVariables(blockLine, item);
                    outputLines.add(processed);
                }
            }

            return endIdx + 1; // 跳过整个循环块
        }

        /**
         * 在行列表中查找包含指定结束标记的行索引
         */
        private static int findEndTag(List<String> lines, int start, String endTag) {
            for (int i = start; i < lines.size(); i++) {
                if (lines.get(i).contains(endTag)) {
                    return i;
                }
            }
            return -1;
        }

        /**
         * 替换行中的简单统计变量
         */
        private static String replaceSimpleVariables(String line,
                                                     int declareTotal, long declarePersonInfoCount, String declarePersonInfoRate,
                                                     long declareUnusedCount, String declareUnusedRate,
                                                     int usedTotal, long usedPersonInfoCount, String appChineseName) {
            String result = line;
            result = result.replace("{{declareTotal}}", String.valueOf(declareTotal));
            result = result.replace("{{declarePersonInfoCount}}", String.valueOf(declarePersonInfoCount));
            result = result.replace("{{declarePersonInfoRate}}", declarePersonInfoRate);
            result = result.replace("{{declareUnusedCount}}", String.valueOf(declareUnusedCount));
            result = result.replace("{{declareUnusedRate}}", declareUnusedRate);
            result = result.replace("{{usedTotal}}", String.valueOf(usedTotal));
            result = result.replace("{{usedPersonInfoCount}}", String.valueOf(usedPersonInfoCount));
            result = result.replace("{{appNameCN}}", appChineseName);
            return result;
        }

        /**
         * 替换行中的数据项变量（用于循环块）
         */
        private static String replaceVariables(String line, Map<String, String> item) {
            String result = line;
            for (Map.Entry<String, String> entry : item.entrySet()) {
                result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
            }
            return result;
        }

        // ---------- 权限扫描相关方法（保持不变） ----------

        private static File findManifestFile(String srcDir) {
            File candidate1 = new File(srcDir, "resources/AndroidManifest.xml");
            if (candidate1.exists()) return candidate1;
            File candidate2 = new File(srcDir, "AndroidManifest.xml");
            if (candidate2.exists()) return candidate2;
            return null;
        }

        private static Set<String> parseManifestPermissions(File manifestFile) {
            Set<String> perms = new TreeSet<>();
            try {
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true);
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document doc = builder.parse(manifestFile);
                String androidNs = "http://schemas.android.com/apk/res/android";
                NodeList usesPermNodes = doc.getElementsByTagName("uses-permission");
                for (int i = 0; i < usesPermNodes.getLength(); i++) {
                    Element element = (Element) usesPermNodes.item(i);
                    String permName = element.getAttributeNS(androidNs, "name");
                    if (permName != null && !permName.isEmpty()) perms.add(permName);
                }
                NodeList usesPermSdk23Nodes = doc.getElementsByTagName("uses-permission-sdk-23");
                for (int i = 0; i < usesPermSdk23Nodes.getLength(); i++) {
                    Element element = (Element) usesPermSdk23Nodes.item(i);
                    String permName = element.getAttributeNS(androidNs, "name");
                    if (permName != null && !permName.isEmpty()) perms.add(permName);
                }
            } catch (ParserConfigurationException | SAXException | IOException e) {
                System.err.println("解析 Manifest 文件失败: " + e.getMessage());
            }
            return perms;
        }

        private static List<PermissionCall> analyzeDirectory(String dirPath) throws IOException {
            List<PermissionCall> result = new ArrayList<>();
            Files.walk(Paths.get(dirPath))
                    .filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .forEach(file -> {
                        try {
                            result.addAll(analyzeFile(file.toFile()));
                        } catch (IOException e) {
                            System.err.println("分析文件出错: " + file + " - " + e.getMessage());
                        }
                    });
            return result;
        }

        private static List<PermissionCall> analyzeFile(File file) throws IOException {
            List<PermissionCall> calls = new ArrayList<>();
            List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
            String fileName = file.getAbsolutePath().replace("\\", "/");
            String className = extractClassName(fileName);
            int lineNumber = 0;
            for (String line : lines) {
                lineNumber++;
                matchPattern(line, "checkSelfPermission\\s*\\(\\s*\"([^\"]+)\"\\s*\\)", className, "checkSelfPermission", lineNumber, calls);
                matchPattern(line, "ContextCompat\\.checkSelfPermission\\s*\\([^,]+,\\s*\"([^\"]+)\"\\s*\\)", className, "ContextCompat.checkSelfPermission", lineNumber, calls);
                matchPattern(line, "ActivityCompat\\.requestPermissions\\s*\\([^,]+,\\s*new\\s+String\\s*\\[\\]\\s*\\{([^}]+)\\}", className, "ActivityCompat.requestPermissions", lineNumber, calls, true);
                matchPattern(line, "requestPermissions\\s*\\(\\s*new\\s+String\\s*\\[\\]\\s*\\{([^}]+)\\}", className, "requestPermissions", lineNumber, calls, true);
                matchPattern(line, "checkPermission\\s*\\(\\s*\"([^\"]+)\"\\s*,", className, "checkPermission", lineNumber, calls);
                matchPattern(line, "enforcePermission\\s*\\(\\s*\"([^\"]+)\"\\s*,", className, "enforcePermission", lineNumber, calls);
                matchPattern(line, "PermissionChecker\\.checkSelfPermission\\s*\\([^,]+,\\s*\"([^\"]+)\"\\s*\\)", className, "PermissionChecker.checkSelfPermission", lineNumber, calls);
                matchPattern(line, "shouldShowRequestPermissionRationale\\s*\\([^,]+,\\s*\"([^\"]+)\"\\s*\\)", className, "shouldShowRequestPermissionRationale", lineNumber, calls);
                // 匹配 Manifest.permission.XXX
                Pattern manifestPattern = Pattern.compile("Manifest\\.permission\\.([A-Z_]+)");
                Matcher m9 = manifestPattern.matcher(line);
                while (m9.find()) {
                    String constName = m9.group(1);
                    String perm = "android.permission." + constName;
                    calls.add(new PermissionCall(className, "Manifest.permission." + constName, perm, lineNumber));
                }
            }
            return calls;
        }

        private static void matchPattern(String line, String pattern, String className, String methodName, int lineNumber, List<PermissionCall> calls) {
            Pattern p = Pattern.compile(pattern);
            Matcher m = p.matcher(line);
            while (m.find()) {
                String perm = m.group(1);
                calls.add(new PermissionCall(className, methodName, perm, lineNumber));
            }
        }

        private static void matchPattern(String line, String pattern, String className, String methodName, int lineNumber, List<PermissionCall> calls, boolean isArray) {
            Pattern p = Pattern.compile(pattern);
            Matcher m = p.matcher(line);
            while (m.find()) {
                String arrayContent = m.group(1);
                Pattern permPattern = Pattern.compile("\"([^\"]+)\"");
                Matcher permMatcher = permPattern.matcher(arrayContent);
                while (permMatcher.find()) {
                    String perm = permMatcher.group(1);
                    calls.add(new PermissionCall(className, methodName, perm, lineNumber));
                }
            }
        }

        private static String extractClassName(String filePath) {
            int index = filePath.indexOf("/sources/");
            if (index == -1) return filePath;
            String relative = filePath.substring(index + 8);
            relative = relative.replace('/', '.');
            if (relative.endsWith(".java")) relative = relative.substring(0, relative.length() - 5);
            return relative;
        }

        // ---------- 新增：敏感 API 扫描相关方法 ----------

        /**
         * 扫描目录下的所有 Java 文件，匹配敏感 API 调用
         */
        private static List<SensitiveDataCall> scanSensitiveApis(String srcDir) throws IOException {
            List<SensitiveDataCall> result = new ArrayList<>();
            Files.walk(Paths.get(srcDir))
                    .filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .forEach(file -> {
                        try {
                            result.addAll(scanFileForSensitiveApis(file.toFile()));
                        } catch (IOException e) {
                            System.err.println("扫描敏感 API 出错: " + file + " - " + e.getMessage());
                        }
                    });
            return result;
        }

        /**
         * 扫描单个 Java 文件，匹配敏感 API 调用
         */
        private static List<SensitiveDataCall> scanFileForSensitiveApis(File file) throws IOException {
            List<SensitiveDataCall> calls = new ArrayList<>();
            List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
            String className = extractClassName(file.getAbsolutePath().replace("\\", "/"));
            int lineNumber = 0;

            // 为每个规则预编译正则，提高效率
            Map<SensitiveRule, Map<ApiInfo, Pattern>> rulePatterns = new HashMap<>();
            for (SensitiveRule rule : sensitiveRules) {
                Map<ApiInfo, Pattern> apiPatterns = new HashMap<>();
                for (ApiInfo api : rule.apis) {
                    // 构造模糊匹配正则：类名.方法名( 忽略中间空格
                    String regex = "\\b" + Pattern.quote(api.method) + "\\s*\\(";
                    apiPatterns.put(api, Pattern.compile(regex));
                }
                rulePatterns.put(rule, apiPatterns);
            }

            for (String line : lines) {
                lineNumber++;
                for (Map.Entry<SensitiveRule, Map<ApiInfo, Pattern>> ruleEntry : rulePatterns.entrySet()) {
                    SensitiveRule rule = ruleEntry.getKey();
                    for (Map.Entry<ApiInfo, Pattern> apiEntry : ruleEntry.getValue().entrySet()) {
                        ApiInfo api = apiEntry.getKey();
                        Pattern p = apiEntry.getValue();
                        Matcher m = p.matcher(line);
                        if (m.find()) {
                            calls.add(new SensitiveDataCall(rule.type, className, api.clazz, api.method, lineNumber, api.permission));                        }
                    }
                }
            }
            return calls;
        }




        // ---------- 内部数据类 ----------
        static class PermissionCall {
            String className;
            String method;
            String permission;
            int lineNumber;

            PermissionCall(String className, String method, String permission, int lineNumber) {
                this.className = className;
                this.method = method;
                this.permission = permission;
                this.lineNumber = lineNumber;
            }
        }

        // 敏感 API 调用记录
        static class SensitiveDataCall {
            String dataType;
            String className;
            String apiClass;
            String apiMethod;
            int lineNumber;  // 改为单个行号，也可用列表
            String requiredPermission; // 从规则中提取

            SensitiveDataCall(String dataType, String className, String apiClass, String apiMethod, int lineNumber, String requiredPermission) {
                this.dataType = dataType;
                this.className = className;
                this.apiClass = apiClass;
                this.apiMethod = apiMethod;
                this.lineNumber = lineNumber;
                this.requiredPermission = requiredPermission;
            }
        }

        // 对应 SensitiveApi.json 的结构
        static class SensitiveRule {
            String type;
            List<ApiInfo> apis;
        }

        static class ApiInfo {
            @SerializedName("class")
            String clazz;  // 使用 clazz 避免关键字冲突
            String method;
            String description;
            String permission;
        }
    }



    /**
     * APK 基本信息提取器（基于 AAPT 和文件哈希）
     */
    public static class ApkInfoExtractor {

        public static Map<String, String> getBasicInfo(String apkFilePath, String aaptPath) {
            Map<String, String> info = new LinkedHashMap<>();

            // 1. 通过 aapt dump badging 获取基本信息
            String badgingOutput = executeAaptCommand(aaptPath, apkFilePath);
            info.put("appName", extractAppName(badgingOutput));
            info.put("packageName", extractPackageName(badgingOutput));
            info.put("versionName", extractVersionName(badgingOutput));
            info.put("versionCode", extractVersionCode(badgingOutput));
            info.put("minSdkVersion", extractMinSdkVersion(badgingOutput));
            info.put("targetSdkVersion", extractTargetSdkVersion(badgingOutput));

            // 2. 安装包文件信息
            File apkFile = new File(apkFilePath);
            info.put("apkFileName", apkFile.getName());
            long fileSizeBytes = apkFile.length();
            String fileSizeMB = String.format("%.2fMB", fileSizeBytes / (1024.0 * 1024.0));
            info.put("appSize", fileSizeMB);

            // 3. 计算安装包哈希（MD5, SHA-1, SHA-256）
            info.put("apkMd5", calculateFileHash(apkFilePath, "MD5"));
            info.put("apkSha1", calculateFileHash(apkFilePath, "SHA-1"));
            info.put("apkSha256", calculateFileHash(apkFilePath, "SHA-256"));

            // 4. 提取签名证书信息（DN 和证书 MD5）
            Map<String, String> certInfo = extractCertificateInfo(apkFilePath);
            info.put("signatureDN", certInfo.getOrDefault("dn", "未知"));
            info.put("certMd5", certInfo.getOrDefault("md5", "未知"));

            // 5. 其他固定字段
            info.put("appType", "其他");          // 可根据需要扩展
            info.put("reinforceInfo", "未知");    // 可后续增加加固检测逻辑
            info.put("analyzeTime", new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                    .format(new java.util.Date()));

            return info;
        }

        private static String executeAaptCommand(String aaptPath, String apkFilePath) {
            // 复制自 AaptParser.executeAaptCommand，但改为静态
            try {
                ProcessBuilder pb = new ProcessBuilder(aaptPath, "dump", "badging", apkFilePath);
                pb.redirectErrorStream(true);
                Process process = pb.start();
                StringBuilder output = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }
                }
                process.waitFor();
                return output.toString();
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
                return "";
            }
        }

        // 以下提取方法均从 AaptParser 复制并调整为静态
        private static String extractPackageName(String output) {
            Pattern pattern = Pattern.compile("package: name='([^']+)'");
            Matcher matcher = pattern.matcher(output);
            return matcher.find() ? matcher.group(1) : "未知";
        }

        private static String extractVersionName(String output) {
            Pattern pattern = Pattern.compile("versionName='([^']*)'");
            Matcher matcher = pattern.matcher(output);
            return matcher.find() ? matcher.group(1) : "未知";
        }

        private static String extractVersionCode(String output) {
            Pattern pattern = Pattern.compile("versionCode='([^']*)'");
            Matcher matcher = pattern.matcher(output);
            return matcher.find() ? matcher.group(1) : "未知";
        }

        private static String extractAppName(String output) {
            Pattern pattern = Pattern.compile("application-label:'([^']*)'");
            Matcher matcher = pattern.matcher(output);
            return matcher.find() ? matcher.group(1) : "未知";
        }

        private static String extractMinSdkVersion(String output) {
            Pattern pattern = Pattern.compile("sdkVersion:'([^']*)'");
            Matcher matcher = pattern.matcher(output);
            return matcher.find() ? matcher.group(1) : null;
        }

        private static String extractTargetSdkVersion(String output) {
            Pattern pattern = Pattern.compile("targetSdkVersion:'([^']*)'");
            Matcher matcher = pattern.matcher(output);
            return matcher.find() ? matcher.group(1) : null;
        }

        // 计算文件哈希（MD5, SHA-1, SHA-256）
        private static String calculateFileHash(String filePath, String algorithm) {
            try (FileInputStream fis = new FileInputStream(filePath)) {
                MessageDigest md = MessageDigest.getInstance(algorithm);
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    md.update(buffer, 0, bytesRead);
                }
                return bytesToHex(md.digest());
            } catch (Exception e) {
                e.printStackTrace();
                return "计算失败";
            }
        }

        // 提取证书 DN 和 MD5
        private static Map<String, String> extractCertificateInfo(String apkFilePath) {
            Map<String, String> result = new HashMap<>();
            result.put("dn", "未知");
            result.put("md5", "未知");

            try (ZipFile zip = new ZipFile(apkFilePath)) {
                Enumeration<? extends ZipEntry> entries = zip.entries();
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

                // 查找签名文件（.RSA, .DSA, .EC）
                List<ZipEntry> sigEntries = new ArrayList<>();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName().toUpperCase(Locale.ROOT);
                    if (name.startsWith("META-INF/") &&
                            (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                        sigEntries.add(entry);
                    }
                }

                for (ZipEntry entry : sigEntries) {
                    try (InputStream is = zip.getInputStream(entry)) {
                        Collection<? extends Certificate> certs = certFactory.generateCertificates(is);
                        if (certs != null && !certs.isEmpty()) {
                            Certificate cert = certs.iterator().next();
                            if (cert instanceof X509Certificate) {
                                X509Certificate x509Cert = (X509Certificate) cert;
                                // DN
                                String dn = x509Cert.getSubjectDN().getName();
                                result.put("dn", dn != null ? dn : "未知");
                                // MD5
                                byte[] encoded = x509Cert.getEncoded();
                                MessageDigest md = MessageDigest.getInstance("MD5");
                                byte[] digest = md.digest(encoded);
                                result.put("md5", bytesToHex(digest));
                                break; // 取第一个证书即可
                            }
                        }
                    } catch (Exception e) {
                        // 忽略，尝试下一个文件
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return result;
        }

        private static String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        }
    }

}