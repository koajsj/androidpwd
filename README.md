# Offline Vault（离线密码库）

一款**完全离线**的 Android 密码管理器，使用 Kotlin + Jetpack Compose 构建。没有网络权限、没有云端、没有服务器——所有数据都加密后保存在本机。

设计灵感来自 1Password、Bitwarden 和 Apple Passwords，但坚持永不离开你的手机。

---

## 亮点功能

- 🔒 密码、备注、自定义字段**以及标题/用户名/网址/标签**采用 **AES-256-GCM** 加密。记录 ID、时间戳、收藏和评分等结构性元数据仍为明文；这不是 SQLCipher 全库加密。
- 🔑 解锁凭据通过 **PBKDF2-HMAC-SHA256**（30 万次迭代，兼顾安全与老设备解锁速度）派生密钥——迭代次数按密码库分别存储，可以随时上调而不会锁死旧密码库
- 🔢 解锁凭据**类型可选**：4 位 PIN、6 位 PIN 或普通密码
- 🧬 **信封加密** —— 随机生成的数据加密密钥（DEK）分别被主密码、密保答案、12 个助记词各包裹一份，任一方式都能恢复数据
- 🧾 **12 个助记词恢复**：仅展示一次、不明文存储，作为忘记主密码且忘记密保答案时的最终恢复手段（设置时需随机抽词校验）
- 👆 通过 Android Keystore + BiometricPrompt(`CryptoObject`) 实现**指纹解锁**（可选）
- 🧮 **强密码生成器**（长度 8–32，可配置字符集）
- 🔤 **离线口令短语**：从内置词库安全随机选取 6、8 或 10 个词；显示基于均匀独立选词的熵估算，不与恢复助记词混用。
- 🩺 **本地安全中心**：弱密码/重复密码筛选、修改入口、会话处理进度、恢复配置与导出状态。记录年龄仅为可选提醒，不扣安全分，也不代表已泄露。
- 🗂 搜索覆盖标题、账号、网址和标签；支持收藏/弱密码筛选、多选收藏、替换标签和回收站删除。
- 📝 **安全字段与 TOTP**：恢复代码、许可证等默认隐藏；可手动录入 Base32 密钥或 `otpauth://totp/` 配置。验证码按 [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) 在本机计算，使用系统时间，不联网校时。将密码与 TOTP 放在同一库中不提供独立第二因素。
- 📊 **密码强度检测**（0–100 分，弱密码与连续字符检测）
- 📥 支持**导入**本应用的加密 JSON 备份或 **Chrome 密码 CSV**
- 📤 支持**导出**加密 JSON（推荐）或明文 CSV（带明确风险提示）
- 🧩 **Android 自动填充**服务：支持**原生应用**（按包名）与**网页**（按域名，含主流浏览器兼容模式）严格匹配；并能在你输入新账号时**主动询问是否保存**到密码库
- 🛡 后台**自动锁定**、可配置的 **FLAG_SECURE 防截屏**、**剪贴板自动清空**，以及多次解锁失败后的指数退避暴力破解延迟
- 🎨 统一的 Material 3 界面：浅色 / 系统深色主题、清晰的信息分组与克制动效；敏感密码默认隐藏

清单中**没有 `android.permission.INTERNET`**。本应用在物理上无法发起任何网络请求。

---

## 构建与运行

### 方式 A —— Android Studio（推荐）
1. 打开 Android Studio（Hedgehog / Iguana 或更新版本，JDK 17）。
2. **File → Open**，选择当前仓库根目录（默认文件夹名为 `vault`）。
3. 等待 Gradle 同步。
4. 在设备或模拟器（minSdk 26 / Android 8.0+）上运行 `app` 配置。

### 方式 B —— 命令行
```bash
cd vault
./gradlew assembleDebug                  # 构建调试版 APK
./gradlew installDebug                   # 安装到已连接的设备
```

APK 会生成在 `app/build/outputs/apk/debug/app-debug.apk`。

### GitHub Actions 持续集成

仓库内置 `Build APK` 工作流，会在推送到 `main` 或手动触发时自动执行：

- 安装 JDK 17 与 Android SDK 35
- 运行 `testDebugUnitTest`
- 构建 `debug APK`
- 上传 `app-debug.apk` 作为构建产物

这条工作流只验证调试版构建，不依赖本地 `keystore.properties`，因此适合用来检查代码变更是否破坏了基础编译链路。

## 手动安装 GitHub Releases 新版本

应用没有在线更新检查或下载功能。需要更新时，请自行使用系统浏览器打开仓库的 GitHub Releases 页面，下载并安装新版；应用本身始终离线。

发布新版时：

1. 在 `app/build.gradle.kts` 中递增 `versionCode`，并更新 `versionName`。
2. 使用与上一版完全相同的发布密钥生成已签名 APK。
3. 创建 GitHub Release，将已签名 APK 和对应的 SHA-256 校验值作为附件上传。
4. 用户从更新页面下载 APK 后，由 Android 系统确认并覆盖安装。

Android 只允许签名证书相同且 `versionCode` 更高的 APK 覆盖安装。发布密钥和密码不得提交到仓库；首次正式发布后必须妥善离线备份该密钥。调试版 APK 使用调试证书，不能被正式发布证书签名的 APK 直接覆盖，迁移前应先导出加密备份。

### 升级时的数据兼容性

当前 Room v6 仅新增 `encryptedCustomFields` 密文列，旧记录默认空值，原密码密文不变。新增字段的 AAD 绑定密码库 ID 与记录 ID；缺少字段的旧备份仍可导入。

新导出采用加密 JSON v2，可读取历史 v1；不再公开明文内容的 SHA-256 校验值，以免形成低成本猜测验证器，完整性由 AES-GCM 认证。导出执行加解密往返核对，并限制在当前 10 MB 导入上限内。文件写入成功不代表设备已实测恢复。

完整 CSV 包含安全字段及 TOTP 密钥，务必作为敏感明文处理。浏览器 CSV 无法保留这些字段，含扩展字段时会拒绝这种有损导出。升级前请自行保存加密备份；旧应用不保证理解新版字段/备份，不能直接降级打开 v6 数据库。

只要用**同一签名密钥**覆盖安装，旧版本的密码库会完整保留，不会丢失或要求重新设置：

- **数据库**：Room 不使用破坏性回退；每次表结构变更都必须提供 `Migration`，缺失迁移只会报错而绝不清库。数据库文件名 `offline_vault.db` 永不更改。
- **密钥材料**：盐值与被包裹的 DEK 存于 DataStore（`offline_vault_secure_prefs`，永不改名）。新增设置项一律带安全默认值，老版本缺失的键不会影响解锁。
- **PBKDF2 迭代次数按库存储**：调低默认值只影响新建密码库；已有密码库继续用创建时的迭代次数解锁。
- **解锁方式向后兼容**：早期"仅主密码"版本升级后仍按密码方式解锁（不会被误判为数字 PIN 而锁死）。
- **助记词恢复**：旧密码库没有助记词不影响使用，可随时在设置中补充启用。

### 启用自动填充（可选）
应用内**设置 → 自动填充**会显示当前是否已启用，并提供「去系统设置开启」按钮，一键跳转到：**系统设置 → 密码、密钥与自动填充 → 自动填充服务 → Offline Vault**。

- 请先至少解锁一次应用，让加密密钥进入内存；该服务只在密码库已解锁时才会**提供**凭据。
- **保存**新账号时，锁定状态下会尝试在内存中加密暂存，待解锁后写入并提示；暂存窗口为 5 分钟。进程被系统回收或暂存失败时不会保存这次输入，请重新触发保存。
- 网站默认严格匹配规范化后的主机名，不自动合并 `www` 或子域名，也不把浏览器本身的原生账号作为网页匹配。包名区分大小写；不明确的跨域 iframe 表单和非默认端口保守拒绝。需要填充别名时，使用手动搜索并确认本次目标，不创建永久放宽的匹配规则。
- **原生应用**开箱即用；**浏览器**需要浏览器本身支持并允许第三方自动填充服务（如 Chrome 需在其设置中开启），本应用已为主流浏览器声明兼容模式。
- 字段识别会同时参考 Android autofill hint、输入类型、控件提示词以及浏览器暴露的 HTML 属性，尽量稳定识别用户名、邮箱、手机号和密码字段。

---

## 项目结构

```
app/src/main/java/com/offlinevault/
├─ MainActivity.kt            # 单 Activity，导航、后台自动锁定、FLAG_SECURE
├─ OfflineVaultApp.kt         # Application + 手动依赖注入容器
├─ AppContainer.kt
├─ security/
│  ├─ CryptoManager.kt        # AES-256-GCM、PBKDF2、SecureRandom 原语
│  ├─ KeyManager.kt           # 初始化 / 解锁 / 找回 / 修改密码 / 助记词 / 生物识别包裹
│  ├─ KeystoreManager.kt      # 与生物识别绑定的 AndroidKeyStore 密钥
│  ├─ SessionManager.kt       # 内存中的 DEK 及解锁状态
│  ├─ MnemonicManager.kt      # 12 个助记词生成 / 校验 / 派生恢复密钥
│  ├─ UnlockThrottle.kt       # 解锁失败的指数退避延迟
│  ├─ EncryptedField.kt       # 可搜索元数据的版本化字段加密
│  ├─ CredentialType.kt       # PIN4 / PIN6 / 密码 凭据类型
│  ├─ LockGuard.kt            # 在系统选择器 / 生物识别期间抑制自动锁定
│  ├─ PasswordStrengthChecker.kt
│  └─ PasswordGenerator.kt
├─ data/
│  ├─ db/AppDatabase.kt
│  ├─ dao/ (VaultDao, PasswordDao)
│  ├─ model/ (VaultEntity, PasswordEntity)
│  ├─ repository/ (VaultRepository, PasswordRepository)   # 加解密逻辑均在此处
│  ├─ preferences/SecurityPreferences.kt                  # DataStore（密钥材料与设置）
│  └─ backup/ (BackupManager, CsvUtils, models)           # JSON/CSV 导入导出
├─ autofill/ (VaultAutofillService, OriginMatcher, PendingAutofillSave)  # 严格匹配 + 保存流程
├─ viewmodel/ (Auth, PasswordList, PasswordEdit, PasswordDetail, Settings)
├─ ui/
│  ├─ theme/ (Color, Type, Theme)
│  ├─ components/ (Components, SecureWindowEffect, PasswordGeneratorSheet)
│  └─ screens/ (Setup, Unlock, Recover, MnemonicUi, PasswordList, PasswordDetail, PasswordEdit, Settings)
└─ utils/ (BiometricHelper, ClipboardHelper, FileIo, Formatters)
```

ViewModel 从不直接访问 DAO —— 一律通过 Repository，所有加解密逻辑都封装在 Repository 内。

---

## 安全模型

```
                 PBKDF2(主密码,   masterSalt)   ──► masterKey   ──┐
随机生成的 256 位 DEK ──┬──────────────────────────────────────────┼─► AES-GCM 包裹 ─► 持久化存储
                 PBKDF2(密保答案, recoverySalt) ──► recoveryKey ──┤
                 PBKDF2(助记词,   mnemonicSalt) ──► mnemonicKey ──┘
```

- **DEK** 用于加密所有密码、备注和元数据，只在解锁状态下存在于内存中（`SessionManager`），达到用户设置的后台锁定时间后清除。
- 主密码、密保答案和助记词**永不存储**。只持久化盐值和被各自包裹的 DEK 副本（保存在 DataStore 中）。
- **解锁** = 派生 `masterKey`，尝试用 AES-GCM 解包 DEK。凭据错误会导致 GCM 认证标签校验失败，因此永远无法得到可用的密钥。
- **找回** = 用密保答案或 12 个助记词解包 DEK，再用新设置的解锁凭据重新包裹一份；找回只重置凭据、不直接进入密码库。数据完整保留；答案/助记词错误则什么也找不回。
- **生物识别** = DEK 额外用一个要求生物识别认证的 AndroidKeyStore AES 密钥包裹一份（`setUserAuthenticationRequired(true)`），通过 BiometricPrompt 的 `CryptoObject` 使用。
- **暴力破解防护** = 连续失败达阈值后按指数退避延迟下一次尝试（`UnlockThrottle`）。
- **短 PIN / 密保答案风险**：退避只限制应用内尝试，不能阻止取得包裹密钥文件后的离线猜测；指纹不会补足短 PIN 的熵。新建默认推荐主密码/长口令，既有 PIN、密保和助记词保持兼容。没有新增与现有 12 个随机助记词重复的恢复码协议，也不把硬件密钥变成唯一恢复依赖。
- **凭据为强制根**：解锁凭据（4 位 PIN / 6 位 PIN / 混合密码）是派生密钥的唯一根，必选；生物识别是可选的便捷层，只是对同一 DEK 的额外包裹，可随时开关。

---

## 隐私与安全加固

针对"流氓 App 扫描 / 上传账号、覆盖钓鱼、截屏窃取"等入侵场景的防护：

- **物理断网**：清单中用 `tools:node="remove"` **强制移除** `INTERNET` / `ACCESS_NETWORK_STATE` / `ACCESS_WIFI_STATE`——即使某个第三方依赖偷偷声明联网权限，合并后也会被删除。没有 INTERNET 权限，系统层面就**无法上传任何数据**。
- **沙箱隔离**：加密数据库与密钥材料存于应用私有目录，其他 App 在未 root 的设备上**无法读取**；`allowBackup=false` + 数据抽取规则全量排除，阻断 `adb backup` 与云备份外泄。
- **排除自动填充捕获**：整个 App 设为 `IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS`，任何第三方自动填充服务 / 输入法都**无法捕获**你在本 App 内输入的主密码或保存的凭据。
- **防截屏 / 防录屏**：`FLAG_SECURE`（默认开启）阻止截图、录屏、投屏以及最近任务缩略图泄露；展示助记词的页面强制开启、不可关闭。
- **剪贴板保护**：复制的密码标记为敏感（Android 13+ 不进剪贴板预览），并在超时后自动清除。
- **内存最小化**：明文 DEK 仅在解锁期间驻留内存，后台超时即清除；自动填充在锁定时不提供任何凭据。

> 仍有 Android 框架层面无法根除的风险需用户自行警惕：用户**主动授予**无障碍权限的恶意服务可能读取屏幕文本，恶意输入法可记录键入。建议不要给来路不明的 App 授予无障碍 / 默认输入法权限。

---

## 说明 / 局限性

- 自动填充服务解析视图结构后**严格匹配**：网页按域名、原生应用按包名（均为精确匹配，绝不做子串匹配，避免钓鱼）。原生应用的凭据以 `androidapp://<包名>` 标识保存。该服务只在密码库已解锁时才提供凭据。
- 网页自动填充依赖浏览器把填充交给第三方服务；不支持第三方填充的浏览器或纯 WebView 无法触发，这是 Android 框架层的限制。
- 从自动填充保存新登录信息会通过系统原生的「保存」弹窗征求用户同意；同一目标且同用户名的条目会更新密码而非新建重复项。
- CSV 导出本质上是明文，导出前会有明确的风险提示弹窗。建议优先使用加密的 JSON 备份用于存储/传输。
