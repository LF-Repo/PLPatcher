## 翻译来自Hy1Fly

# 解锁 Fastboot — Oppo 联发科（通用）Bootloader 解锁工具
本仓库中的脚本用于基于原厂预加载器（preloader）生成一个修改版，其中将 fastboot 锁标志更改为已解锁状态。

## 通用信息
* 已发现在 Realme 设备上，刷入修改后的 preloader 后，将无法通过按键进入 fastboot，但仍可通过例如 `adb reboot bootloader` 命令进入 fastboot。
* 在 MT6765 + Android 10 上应用补丁无法解锁 fastboot，原因正在调查中...
* 部分 Android 15+ 设备在应用补丁后也无法解锁 fastboot，目前原因未知。
* 无法绕过校验完整编辑 RAW 分区，因此本仓库无法帮助你绕过许多 Oppo 设备的 LK 校验。

---

## 操作说明
* 下载并安装 [Python](https://www.python.org/downloads) 3.4 及以上版本（用于 mtkclient 时建议 3.10-3.13）
* 使用 [mtkclient](https://github.com/bkerler/mtkclient) 及其图形界面，或 [GeekFlashTool](https://gitee.com/geekflashtool)，或 [Penumbra](https://github.com/shomykohai/penumbra) 来读取你 Oppo 设备的预加载器（boot1）备份。如果你的当前活动槽位是 B，则需对 boot2 应用补丁。如果没有 A/B 槽位，则仍应对 boot1 应用补丁。
* 将 preloader 备份文件放在与 `preloader_path.py` 相同的文件夹下，并确保命名为 `boot1.bin`，然后双击运行 Python 脚本。或者使用命令行：`path_preloader.py [输入文件]`
* 脚本运行完成后，修改后的 preloader 将位于 `preloader_path` 文件夹中，文件名为 `boot1.bin`
* 将生成的 preloader 写入设备，使用所支持的刷写工具
* 务必在开发者选项中开启“OEM 解锁”
* 使用 adb 命令 `adb reboot bootloader` 进入解锁的 fastboot 模式
* 进入 fastboot 后，使用命令 `fastboot flashing unlock`
* 通过按音量上键或下键确认解锁 Bootloader。请仔细阅读设备屏幕上解锁请求后的提示文字
* 恭喜，Bootloader 解锁过程完成...
---
## 补丁创建成功日志示例
```
Dev. Max_Goblin - 4pda
模式: 默认
找到 boot1.bin 状态: 成功
内存类型: EMMC_BOOT
找到标志块状态: 成功
锁定状态: 22 (锁定)
写入零区域: 0x800:0x2000
跳转偏移代码: 0x800 至 0x2000
--------------------
更改 BRLYT 偏移量
0x20d: 08 -> 20
0x21d: 08 -> 20
0x211: 08 -> 10
0x212: 08 -> 10
0x221: 08 -> 10
0x222: 08 -> 10
--------------------
写入标志块至: 0x1000
Fastboot 锁定状态: 0x22 -> 00
创建新的 preloader 至: C:\mtkclient\mtkclient_2.0.1\preloader_path\boot1.bin
按 Enter 关闭
```
---
## 支持设备信息
| 型号                  | 设备代码                 | SoC                | SoC ID            | 状态                                                                          |
|------------------------|-----------------------------|--------------------|-------------------|---------------------------------------------------------------------------------|
| Oppo A9X               | PCEM00 & PCET00             | Helio P70          | MT6771            | MTKClient: 完全支持                                                         |
| Oppo A15               | CPH2185                     | Helio P35          | MT6765            | MTKClient: 支持，补丁未能解锁 fastboot，仅测试过 Android 10 |
| Oppo A17               | CPH2477                     | Helio G35          | MT6765            | MTKClient: 完全支持                                                         |
| Oppo A17               | CPH2477                     | Helio G35          | MT6765            | MTKClient: 完全支持                                                         |
| Oppo A17K              | CPH2471                     | Helio G35          | MT6765            | MTKClient: 完全支持                                                         |
| Oppo A18               | CPH2591                     | Helio G85          | MT6768/MT6769     | MTKClient: DAA 图形界面和命令行存在问题，auth_sv5.auth 未测试                       |
| Oppo A35               | PEFM00                      | Helio P35          | MT6765            | MTKClient: 支持，补丁未能解锁 fastboot                             |
| Oppo A54 4G            | CPH2239                     | Helio G35          | MT6765            | MTKClient: DAA 图形界面和命令行存在问题，auth_sv5.auth 未测试                   |
| Oppo A55 4G            | CPH2325                     | Helio G35          | MT6765            | MTKClient: 完全支持                                                         |
| Oppo A55 5G            | CPHPEMM00 & PEMT00          | Dimensity 700      | MT6833            | GeekFlashTool: 完全支持                                                     |
| Oppo A56 5G            | PFVM110                     | Dimensity 700      | MT6833            | MTKClient: 完全支持                                                         |
| Oppo A58 4G            | CPH2577                     | Helio G85          | MT6768/MT6769     | MTKClient: DAA 图形界面和命令行存在问题，auth_sv5.auth 未测试                   |
| Oppo A58x              | PHJ110                      | Dimensity 700      | MT6833            | GeekFlashTool: 仅支持 Android 12；[O+ Support Tool]: 完全支持         |
| Oppo A73 5G            | CPH2161                     | Dimensity 720      | MT6853            | MTKClient: 图形界面支持，无图形界面需使用 auth_sv5.auth。        |
| Oppo A93s              | PFGM00                      | Dimensity 700      | MT6833            | MTKClient: 完全支持                                                         |
| Oppo F31 Pro 5G        | CPH2763                     | Dimensity 7300     | MT6878            | [O+ Support Tool]: 支持；补丁有效。真奇怪... Android 16 未测试      |
| Oppo Find X8s          | PKT110                      | Dimensity 9400+    | MT6991            | [O+ Support Tool]: 支持；fastboot 未能解锁                           |
| Oppo K9 Pro            | PEYM00                      | Dimensity 1200     | MT6893            | GeekFlashTool: 完全支持                                                     |
| Oppo Pad 2             | OPD2201                     | Dimensity 9000     | MT6983            | GeekFlashTool: 完全支持                                                     |
| Oppo Reno 10 5g        | CPH2531                     | Dimensity 7050     | MT6877V           | MTKClient: DAA 图形界面和命令行存在问题，auth_sv5.auth 未测试                   |
| Oppo Reno 11 5g        | CPH2599                     | Dimensity 7050     | MT6877V           | MTKClient, Penumbra, UnlockTool: PLPort: DAA 问题；Brom: DA ARB 问题。补丁未测试                   |
| Oppo Reno 11F 5g       | CPH2603                     | Dimensity 7050     | MT6877V           | MTKClient: DAA 图形界面和命令行存在问题，auth_sv5.auth 未测试                |
| Oppo Reno 3 5G         | CPH2125                     | Dimensity 1000L    | MT6885            | MTKClient: 完全支持                                                         |
| Oppo Reno 4 Lite       | CPH2125                     | Helio P95          | MT6779            | MTKClient: 完全支持                                                         |
| Oppo Reno 5 Lite       | CPH2205                     | Helio P95          | MT6779            | MTKClient: 完全支持                                                         |
| Oppo Reno 5 Z          | CPH2211                     | Dimensity 800U     | MT6853            | MTKClient + [DA](https://archive.diablosat.cc/firmwares/amt-dumps/Oppo_Realme_Oneplus_DA/DA_BR_MT6853.bin): 完全支持                                                                                                                                                   |
| Oppo Reno 6 5G         | CPH2251 & PEQM00            | Dimensity 900      | MT6877            | GeekFlashTool: 完全支持，mtkclient 可能也支持。                |
| Realme 12 Plus         | RMX3867                     | Dimensity 7050     | MT6877            | MTKClient + [DA MT6877](https://archive.diablosat.cc/firmwares/amt-dumps/Oppo_Realme_Oneplus_DA/): 支持，补丁未能解锁 fastboot，可能由于 Android 15+ 导致，Android 14 未测试                                                              |
| Realme С11 & C12 & C15 | RMX2185 & RMX2189 & RMX2180 | Dimensity 1200     | MT6893            | GeekFlashTool: 完全支持                                                     |
| Realme GT Neo          | RMX3031                     | Dimensity 1200     | MT6893            | GeekFlashTool: 完全支持                                                     |
| Realme GT Neo 2T       | RMX3357 & RE5469            | Dimensity 1200     | MT6893            | GeekFlashTool: 完全支持                                                     |
| Realme Q2 Pro          | RMX2173                     | Dimensity 800U     | MT6853            | MTKClient + [DA](https://archive.diablosat.cc/firmwares/amt-dumps/Oppo_Realme_Oneplus_DA/DA_BR_MT6853.bin): 完全支持                                                                 |
| Realme V11 5G          | RMX3121 & RMX3122           | Dimensity 700      | MT6833            | GeekFlashTool: 完全支持                                                     |

#### DAA 问题并不一定意味着不支持解锁，尤其是在 auth_sv5.auth 未测试的情况下。除了 mtkclient 之外，你也可以尝试不同的工具。
#### 如果你使用此补丁成功解锁了任何 Oppo 设备的 Bootloader，请在 Issues 中反馈，告知该新设备型号、此方法有效，最好同时提供原始的 preloader 和修改后的补丁，并注明 Android 版本、以及你用于读写 preloader 的工具。如果该方法无效，也欢迎反馈。你也可以通过 Telegram 联系我。

## 免责声明

本软件按 **“现状”** 提供，不附带任何明示或暗示的保证。使用本工具即表示您确认：
* 修改预加载器或刷写修改后的镜像具有 **导致设备永久损坏（变砖）的高风险**。
* 您对因使用、误用或无法使用本软件所产生的任何后果承担全部责任。
* 本项目的维护者和贡献者 **对任何损坏、数据丢失、设备故障或法律问题不承担任何责任**。
* 本项目仅用于 **教育和研究目的**。**不得用于非法或未经授权的用途**。
* 通过 OTA 升级会覆盖您的预加载器，但如果您按预期使用本仓库，只会导致 fastboot 被屏蔽，而不会导致设备变砖。
* 您也可以自行更新预加载器的 RAW 部分，这通常不会引发问题，但请注意，更新 RAW 部分可能会增加额外的锁或修复。此外，从 Android 14 更新到 Android 15 可能会导致不可预测的结果。

请仅在完全理解风险和影响的情况下继续操作。

## 附加信息
在俄罗斯 4pda 论坛上，用户 Max_Goblin 提供了非常详细的 [说明](https://4pda.to/forum/index.php?showtopic=1059838&view=findpost&p=136154776)，包括在 Windows 上详细安装 mtkclient、创建和恢复备份、图形界面使用详解，以及手动创建 preloader 补丁的说明。

---
## 本项目采用 AGPL-3.0 许可证。详情请参阅 [LICENSE](LICENSE) 文件。