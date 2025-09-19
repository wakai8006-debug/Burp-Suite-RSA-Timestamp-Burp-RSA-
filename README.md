# Burp-Suite-RSA-Timestamp-Burp-RSA
RSA Timestamp Payload Generator (UI) — Burp Suite 插件，实时生成动态 RSA 时间戳
---

# 1. RSA Timestamp Payload Generator (UI) for Burp Suite

**A Burp Jython extension for generating RSA-encrypted timestamp payloads dynamically with UI support.**

---

## 2. 简介 / Description

`RSA Timestamp Payload Generator (UI)` 是一个 Burp Suite 插件，专门用于生成基于 RSA 公钥加密的时间戳 payload，可直接用于 Intruder 或 Repeater。

**主要功能：**

1. 粘贴动态 RSA 公钥 (PEM 格式)
2. 生成当前时间戳（秒/毫秒可选）
3. 使用 PKCS#1 v1.5 填充方式进行 RSA 加密
4. Base64 编码生成 payload
5. 支持包装字符（可选）或直接输出
6. 可配置 payload 数量限制
7. 实时生成 payload，支持爆破或重放攻击测试

**适用场景：** 测试接口安全性、时间戳签名验证、密码爆破等。

---

## 3. 安装方法 / Installation

1. 下载 `rsa_ts_generator_ui.py` 文件。
2. 打开 Burp Suite → **Extender** → **Extensions** → **Add**。
3. 选择：

   * **Extension Type:** Python
   * **Extension File:** `rsa_ts_generator_ui.py`
  <img width="1126" height="570" alt="image" src="https://github.com/user-attachments/assets/f656dae5-65a5-4072-a1b4-53cbea25212f" />

4. 安装完成后，Burp 会在右侧 Tabs 添加 **RSA-ts-gen**。
<img width="929" height="505" alt="image" src="https://github.com/user-attachments/assets/84048256-c973-472f-844e-a6ffd7cfd8dc" />

---

## 4. 使用方法 / Usage

1. 在 UI 中粘贴目标服务的 RSA 公钥（PEM 格式）。
2. 配置选项：

   1. **Milliseconds (13-digit)** / **Seconds (10-digit)**
   2. **Payload limit**（0 = unlimited）
   3. **Wrap with §…§**（可选包装字符）
3. 点击 **Save Settings**。
4. 在 Intruder 的 Payloads 选项中选择 `RSA-ts-generator-ui`。
5. 将生成的 payload 替换请求中的 `random` 字段。
6. 启动攻击，实时生成 RSA 加密时间戳 payload。
<img width="924" height="513" alt="image" src="https://github.com/user-attachments/assets/d3fc0659-7a23-474d-9757-c4ecf5a410a2" />

---

## 5. 工作流程 / Workflow

```
1. 用户输入目标公钥 (PEM)
2. 插件解析公钥
3. 生成当前时间戳（秒或毫秒）
4. RSA/PKCS1Padding 加密
5. Base64 编码生成 payload
6. Intruder 替换请求字段 (random)
7. 发送到目标接口
8. 接口返回结果，支持爆破或验证
```

---

## 6. 示例

前端请求数据示例：

```json
{
  "username": "admin",
  "password": "123456",
  "random": "<RSA-ENCODED-TIMESTAMP>"
}
```

插件会自动生成 `<RSA-ENCODED-TIMESTAMP>`，保证时间戳实时加密并可直接发送。
<img width="1670" height="828" alt="image" src="https://github.com/user-attachments/assets/36fc2e5d-5f9b-46eb-aa83-fad344520a2d" />
<img width="496" height="259" alt="image" src="https://github.com/user-attachments/assets/56a9a7d1-6981-4d98-94f9-50f5ad6778b7" />


---

## 7. 注意事项 / Notes

1. 公钥必须为 PEM 格式，包含 `-----BEGIN PUBLIC KEY-----` 和 `-----END PUBLIC KEY-----`。
2. 建议在 Intruder 配置中设置合适的发送速率，以避免对目标服务器造成压力。
3. 如果使用包装字符（§…§），确保目标接口能正确解析。
4. 支持动态更新公钥，无需重启 Burp Suite。
5. 插件基于 Jython，确保已正确安装 Burp Python 环境。

---

