package com.universal.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UniversalEncryptBurp implements BurpExtension {
    public MontoyaApi api;
    private Logging logging;
    private UserInterface ui;

    // 配置项
    private String encryptAlgorithm;
    private String aesKey;
    private String aesIv;
    private String hmacKey;
    private String rsaPrivateKey;
    private String rsaPublicKey;
    private String paramName;
    private boolean isJsonFormat;
    private boolean isEncryptUppercase;

    // 配置面板组件
    private JComboBox<String> algorithmCombo;
    private JTextField aesKeyField;
    private JTextField aesIvField;
    private JTextField hmacKeyField;
    private JTextArea rsaPrivateKeyArea;
    private JTextArea rsaPublicKeyArea;
    private JTextField paramField;
    private JCheckBox jsonCheckBox;
    private JCheckBox uppercaseCheckBox;
    private JButton saveBtn;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.api.extension().setName("万能加密工具箱");
        this.logging = this.api.logging();
        this.ui = this.api.userInterface();

        // 初始化默认配置
        this.encryptAlgorithm = "AES_ECB";
        this.aesKey = "1234567890abcdef";
        this.aesIv = "1234567890abcdef";
        this.hmacKey = "hmacSecretKey";
        this.rsaPrivateKey = "";
        this.rsaPublicKey = "";
        this.paramName = "pwd";
        this.isJsonFormat = false;
        this.isEncryptUppercase = false;

        // 创建配置面板
        createConfigPanel();

        // 加载成功日志
        logging.logToOutput("✅ 万能加密工具箱加载成功！");
        logging.logToOutput("🔥 支持算法：AES_ECB/AES_CBC、MD5、SHA1/SHA256/SHA512、HMAC_SHA256、RSA");
        logging.logToOutput("📋 支持格式：JSON自动识别、表单格式");
        logging.logToOutput("⚙️ 配置面板已在Burp顶部打开，直接修改即可生效～");

        // 注册HTTP拦截器
        Http http = this.api.http();
        http.registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                if (requestToBeSent.toolSource().isFromTool(ToolType.REPEATER)) {
                    String requestData = requestToBeSent.bodyToString();
                    logging.logToOutput("📥 捕获Repeater请求，原始Body：" + requestData);

                    // 自动识别请求格式
                    autoDetectRequestFormat(requestData);

                    // 提取目标参数的原始值
                    String originalValue = extractOriginalValue(requestData);
                    if (originalValue == null) {
                        logging.logToOutput("⚠️ 未找到参数【" + paramName + "】，直接放行");
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                    }

                    // 按选择的算法加密
                    String encryptValue = encryptByAlgorithm(originalValue);
                    if (encryptValue == null || encryptValue.isEmpty()) {
                        logging.logToError("❌ " + encryptAlgorithm + "加密失败，直接放行");
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                    }

                    // 输出加密详情
                    String caseDesc = isEncryptUppercase ? "大写" : "小写";
                    logging.logToOutput("🔒 加密详情：明文=" + originalValue + " → " + encryptAlgorithm + "(" + caseDesc + ")=" + encryptValue);
                    logging.logToOutput("📋 当前配置：算法=" + encryptAlgorithm + " | 参数名=" + paramName + " | 格式=" + (isJsonFormat ? "JSON" : "表单") + " | 大小写=" + caseDesc);

                    // 替换请求体中的参数值
                    String newRequestBody = replaceParamValue(requestData, encryptValue);
                    logging.logToOutput("📤 替换后请求Body：" + newRequestBody);

                    // 发送修改后的请求
                    HttpRequest newReq = requestToBeSent.withBody(newRequestBody);
                    return RequestToBeSentAction.continueWith(newReq);
                }
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });
    }

    // 创建配置面板
    private void createConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("万能加密工具箱配置"));
        panel.setPreferredSize(new Dimension(650, 450));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 加密算法选择
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("🔑 选择加密算法："), gbc);
        gbc.gridx = 1;
        algorithmCombo = new JComboBox<>(new String[]{
                "AES_ECB", "AES_CBC",
                "MD5", "SHA1", "SHA256", "SHA512",
                "HMAC_SHA256",
                "RSA"
        });
        algorithmCombo.setSelectedItem(encryptAlgorithm);
        algorithmCombo.addActionListener(e -> updatePanelComponents());
        panel.add(algorithmCombo, gbc);

        // AES密钥
        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("🔐 AES密钥（16/32位）："), gbc);
        gbc.gridx = 1;
        aesKeyField = new JTextField(aesKey);
        aesKeyField.setEnabled(encryptAlgorithm.startsWith("AES"));
        aesKeyField.setToolTipText("AES算法必填，输入16位或32位字符串");
        panel.add(aesKeyField, gbc);

        // AES CBC IV
        gbc.gridx = 0;
        gbc.gridy = 2;
        panel.add(new JLabel("🔄 AES CBC IV（16位）："), gbc);
        gbc.gridx = 1;
        aesIvField = new JTextField(aesIv);
        aesIvField.setEnabled(encryptAlgorithm.equals("AES_CBC"));
        aesIvField.setToolTipText("AES_CBC模式必填，必须16位字符串");
        panel.add(aesIvField, gbc);

        // HMAC密钥
        gbc.gridx = 0;
        gbc.gridy = 3;
        panel.add(new JLabel("🔑 HMAC密钥："), gbc);
        gbc.gridx = 1;
        hmacKeyField = new JTextField(hmacKey);
        hmacKeyField.setEnabled(encryptAlgorithm.equals("HMAC_SHA256"));
        panel.add(hmacKeyField, gbc);

        // RSA私钥
        gbc.gridx = 0;
        gbc.gridy = 4;
        panel.add(new JLabel("🔒 RSA私钥（PEM）："), gbc);
        gbc.gridx = 1;
        rsaPrivateKeyArea = new JTextArea(rsaPrivateKey, 3, 25);
        rsaPrivateKeyArea.setBorder(BorderFactory.createEtchedBorder());
        rsaPrivateKeyArea.setEnabled(encryptAlgorithm.equals("RSA"));
        rsaPrivateKeyArea.setToolTipText("输入PEM格式私钥（去掉首尾行和空格）");
        panel.add(new JScrollPane(rsaPrivateKeyArea), gbc);

        // RSA公钥
        gbc.gridx = 0;
        gbc.gridy = 5;
        panel.add(new JLabel("🔑 RSA公钥（PEM）："), gbc);
        gbc.gridx = 1;
        rsaPublicKeyArea = new JTextArea(rsaPublicKey, 3, 25);
        rsaPublicKeyArea.setBorder(BorderFactory.createEtchedBorder());
        rsaPublicKeyArea.setEnabled(encryptAlgorithm.equals("RSA"));
        rsaPublicKeyArea.setToolTipText("输入PEM格式公钥（去掉首尾行和空格）");
        panel.add(new JScrollPane(rsaPublicKeyArea), gbc);

        // 目标参数名
        gbc.gridx = 0;
        gbc.gridy = 6;
        panel.add(new JLabel("📝 目标参数名："), gbc);
        gbc.gridx = 1;
        paramField = new JTextField(paramName);
        paramField.setToolTipText("输入要加密的参数名，如pwd、sign");
        panel.add(paramField, gbc);

        // JSON格式切换
        gbc.gridx = 0;
        gbc.gridy = 7;
        panel.add(new JLabel("📄 JSON格式请求？"), gbc);
        gbc.gridx = 1;
        jsonCheckBox = new JCheckBox();
        jsonCheckBox.setSelected(isJsonFormat);
        panel.add(jsonCheckBox, gbc);

        // 加密结果大小写
        gbc.gridx = 0;
        gbc.gridy = 8;
        panel.add(new JLabel("🔤 结果是否大写？"), gbc);
        gbc.gridx = 1;
        uppercaseCheckBox = new JCheckBox();
        uppercaseCheckBox.setSelected(isEncryptUppercase);
        uppercaseCheckBox.setToolTipText("MD5/SHA/HMAC结果支持大小写切换");
        panel.add(uppercaseCheckBox, gbc);

        // 保存配置按钮
        gbc.gridx = 0;
        gbc.gridy = 9;
        gbc.gridwidth = 2;
        saveBtn = new JButton("💾 保存配置");
        saveBtn.addActionListener(e -> saveConfig());
        panel.add(saveBtn, gbc);

        ui.registerSuiteTab("万能加密工具箱", panel);
    }

    // 面板组件联动
    private void updatePanelComponents() {
        String selectedAlg = (String) algorithmCombo.getSelectedItem();
        aesKeyField.setEnabled(selectedAlg.startsWith("AES"));
        aesIvField.setEnabled(selectedAlg.equals("AES_CBC"));
        hmacKeyField.setEnabled(selectedAlg.equals("HMAC_SHA256"));
        rsaPrivateKeyArea.setEnabled(selectedAlg.equals("RSA"));
        rsaPublicKeyArea.setEnabled(selectedAlg.equals("RSA"));
    }

    // 保存配置
    private void saveConfig() {
        this.encryptAlgorithm = (String) algorithmCombo.getSelectedItem();
        this.aesKey = aesKeyField.getText().trim();
        this.aesIv = aesIvField.getText().trim();
        this.hmacKey = hmacKeyField.getText().trim();
        this.rsaPrivateKey = rsaPrivateKeyArea.getText().trim();
        this.rsaPublicKey = rsaPublicKeyArea.getText().trim();
        this.paramName = paramField.getText().trim();
        this.isJsonFormat = jsonCheckBox.isSelected();
        this.isEncryptUppercase = uppercaseCheckBox.isSelected();

        // 合法性校验
        if (encryptAlgorithm.startsWith("AES")) {
            if (aesKey.isEmpty()) {
                JOptionPane.showMessageDialog(null, "AES算法密钥不能为空！", "❌ 配置错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (encryptAlgorithm.equals("AES_CBC") && aesIv.isEmpty()) {
                JOptionPane.showMessageDialog(null, "AES_CBC模式IV不能为空！", "❌ 配置错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        if (encryptAlgorithm.equals("HMAC_SHA256") && hmacKey.isEmpty()) {
            JOptionPane.showMessageDialog(null, "HMAC_SHA256密钥不能为空！", "❌ 配置错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (encryptAlgorithm.equals("RSA") && (rsaPrivateKey.isEmpty() || rsaPublicKey.isEmpty())) {
            JOptionPane.showMessageDialog(null, "RSA算法私钥和公钥不能为空！", "❌ 配置错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (paramName.isEmpty()) {
            JOptionPane.showMessageDialog(null, "目标参数名不能为空！", "❌ 配置错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        logging.logToOutput("✅ 配置保存成功：算法=" + encryptAlgorithm + " | 参数名=" + paramName + " | 大小写=" + (isEncryptUppercase ? "大写" : "小写"));
        JOptionPane.showMessageDialog(null, "配置保存成功！", "✅ 成功", JOptionPane.INFORMATION_MESSAGE);
    }

    // 核心加密方法
    private String encryptByAlgorithm(String data) {
        switch (encryptAlgorithm) {
            case "AES_ECB":
                return aesEcbEncrypt(data);
            case "AES_CBC":
                return aesCbcEncrypt(data);
            case "MD5":
                return md5Encrypt(data);
            case "SHA1":
                return sha1Encrypt(data);
            case "SHA256":
                return sha256Encrypt(data);
            case "SHA512":
                return sha512Encrypt(data);
            case "HMAC_SHA256":
                return hmacSha256Encrypt(data);
            case "RSA":
                return rsaEncrypt(data);
            default:
                logging.logToError("❌ 不支持的加密算法：" + encryptAlgorithm);
                return null;
        }
    }

    // AES_ECB加密
    private String aesEcbEncrypt(String data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(aesKey.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            logging.logToError("❌ AES_ECB加密异常：" + e.getMessage());
            return null;
        }
    }

    // AES_CBC加密
    private String aesCbcEncrypt(String data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(aesKey.getBytes(StandardCharsets.UTF_8), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(aesIv.getBytes(StandardCharsets.UTF_8));
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            logging.logToError("❌ AES_CBC加密异常：" + e.getMessage());
            return null;
        }
    }

    // MD5加密
    private String md5Encrypt(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return byteToHex(hashBytes);
        } catch (Exception e) {
            logging.logToError("❌ MD5加密异常：" + e.getMessage());
            return null;
        }
    }

    // SHA1加密
    private String sha1Encrypt(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return byteToHex(hashBytes);
        } catch (Exception e) {
            logging.logToError("❌ SHA1加密异常：" + e.getMessage());
            return null;
        }
    }

    // SHA256加密
    private String sha256Encrypt(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return byteToHex(hashBytes);
        } catch (Exception e) {
            logging.logToError("❌ SHA256加密异常：" + e.getMessage());
            return null;
        }
    }

    // SHA512加密
    private String sha512Encrypt(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return byteToHex(hashBytes);
        } catch (Exception e) {
            logging.logToError("❌ SHA512加密异常：" + e.getMessage());
            return null;
        }
    }

    // HMAC_SHA256加密
    private String hmacSha256Encrypt(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(hmacKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return byteToHex(hmacBytes);
        } catch (Exception e) {
            logging.logToError("❌ HMAC_SHA256加密异常：" + e.getMessage());
            return null;
        }
    }

    // RSA加密
    private String rsaEncrypt(String data) {
        try {
            String publicKeyPem = rsaPublicKey.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPem);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            logging.logToError("❌ RSA加密异常：" + e.getMessage());
            return null;
        }
    }

    // 字节数组转十六进制
    private String byteToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return isEncryptUppercase ? sb.toString().toUpperCase() : sb.toString();
    }

    // 自动识别请求格式
    private void autoDetectRequestFormat(String requestBody) {
        if (requestBody.startsWith("{") && requestBody.endsWith("}") && requestBody.contains(":")) {
            isJsonFormat = true;
            jsonCheckBox.setSelected(true);
        } else {
            isJsonFormat = false;
            jsonCheckBox.setSelected(false);
        }
    }

    // 提取目标参数值
    private String extractOriginalValue(String requestBody) {
        String regex = isJsonFormat ?
                "\"" + paramName + "\":\"([^\"]*)\"" :
                paramName + "=([^&]*)";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(requestBody);
        return matcher.find() ? matcher.group(1) : null;
    }

    // 替换参数值
    private String replaceParamValue(String requestBody, String encryptValue) {
        String regex = isJsonFormat ?
                "\"" + paramName + "\":\"([^\"]*)\"" :
                paramName + "=[^&]*";

        String replacement = isJsonFormat ?
                "\"" + paramName + "\":\"" + encryptValue + "\"" :
                paramName + "=" + encryptValue;

        return requestBody.replaceAll(regex, replacement);
    }
}
