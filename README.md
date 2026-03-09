# universal-encrypt-burp
Burp Suite万能加密插件 | 自动识别JSON/表单 | 支持AES/MD5/SHA/HMAC/RSA | 逆向工程专用


```markdown
# UniversalEncryptBurp 🔐

> Burp Suite万能加密插件 | 自动识别+动态加密 | 支持8种算法 | 逆向工程专用

[![Java Version](https://img.shields.io/badge/Java-8+-orange.svg)](https://java.com)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Montoya-ff69b4)](https://portswigger.net/burp)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 📌 简介

**UniversalEncryptBurp** 是一款专为**安全测试/逆向工程**设计的Burp Suite插件。它能在你发送请求时**自动加密目标参数**，支持JSON和表单格式，帮助测试人员快速验证加密逻辑。

## ✨ 特性

### 🔥 8种加密算法
| 类型 | 算法 |
|------|------|
| 对称加密 | AES_ECB、AES_CBC |
| 哈希算法 | MD5、SHA1、SHA256、SHA512 |
| 消息认证码 | HMAC_SHA256 |
| 非对称加密 | RSA（公钥加密） |

### 🎯 核心功能
- ✅ **自动识别请求格式**（JSON/表单）
- ✅ **实时拦截Repeater请求**，动态加密
- ✅ **可视化配置面板**（无需修改代码）
- ✅ **加密结果大小写可选**（哈希/HMAC适用）
- ✅ **实时日志输出**，调试无忧

### 🖥️ 配置面板
- 算法选择下拉框
- AES密钥/IV输入
- HMAC密钥输入
- RSA公私钥输入（PEM格式）
- 目标参数名自定义
- JSON格式切换
- 大小写切换

## 🚀 安装使用

### 环境要求
- Burp Suite（支持Montoya API）
- Java 8+

### 安装步骤
1. 下载 `UniversalEncryptBurp.java`
2. 编译：`javac -cp "burp-api.jar" UniversalEncryptBurp.java`
3. Burp Suite → Extensions → Add
4. Extension Type: Java
5. 选择编译后的 `.class` 文件

### 使用方法
1. 打开Burp顶部Tab **"万能加密工具箱"**
2. 配置算法和参数
3. 在Repeater中发送请求
4. 插件自动拦截并加密目标参数

## 📖 使用示例

### 场景1：表单格式MD5加密
```
原始请求：POST /login  pwd=123456
配置：算法=MD5，参数名=pwd
自动替换为：pwd=e10adc3949ba59abbe56e057f20f883e
```

### 场景2：JSON格式AES加密
```json
原始请求：{"pwd":"123456"}
配置：算法=AES_ECB，密钥=1234567890abcdef
自动替换为：{"pwd":"aBcDeFgHiJkLmNoP="}
```

## ⚙️ 配置说明

| 配置项 | 说明 |
|--------|------|
| 加密算法 | 选择要使用的算法 |
| AES密钥 | 16位或32位字符串 |
| AES IV | AES_CBC模式需要，16位 |
| HMAC密钥 | HMAC_SHA256专用 |
| RSA公私钥 | PEM格式（去掉首尾行和空格） |
| 目标参数名 | 要加密的参数，如pwd/sign |
| JSON格式 | 手动切换/自动识别 |
| 大小写 | 哈希结果是否大写 |

## 🔧 二次开发

### 新增算法
1. 在 `encryptByAlgorithm()` 添加case
2. 实现具体加密方法
3. 在配置面板添加对应输入项

### 修改UI
- 编辑 `createConfigPanel()` 方法
- 使用GridBagLayout自由布局

## 📝 注意事项
- 默认密钥仅供测试，生产环境请替换
- RSA需要正确格式的PEM密钥
- 仅拦截Repeater工具请求

## 🤝 贡献指南
欢迎PR！如果有新的算法需求或bug修复，请提Issue。

## 📄 License
MIT © 2025 UniversalEncryptBurp

## ⭐ 鼓励一下
如果这个工具帮到了你，请给个Star，让更多安全人看到！

```

