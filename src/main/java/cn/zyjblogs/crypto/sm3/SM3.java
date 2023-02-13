package cn.zyjblogs.crypto.sm3;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * 国密SM3摘要算法
 */
public class SM3 {

    public static String digest(String input) {
        // 创建摘要器
        SM3Digest sm3Digest = new SM3Digest();
        // 解析输入数据
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        // 构造输出数据缓冲区
        byte[] out = new byte[32];
        // 设置待摘要字节数据
        sm3Digest.update(bytes, 0, bytes.length);
        // 执行摘要
        sm3Digest.doFinal(out, 0);
        // 返回HEX字符串
        return Hex.toHexString(out).toUpperCase(Locale.ROOT);
    }


    public static String hmac(String key, String data) {
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        KeyParameter keyParameter = new KeyParameter(key.getBytes(StandardCharsets.UTF_8));
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        mac.update(bytes, 0, bytes.length);
        byte[] out = new byte[32];
        mac.doFinal(out, 0);
        return Hex.toHexString(out).toUpperCase(Locale.ROOT);
    }

    public static boolean verify(String data, String hash) {
        String srcHash = digest(data);
        return hash.equals(srcHash);
    }

    public static boolean verify(String key, String data, String hmac) {
        String srcHmac = hmac(key, data);
        return hmac.equals(srcHmac);
    }

    public static void main(String[] args) {
        String a = SM3.digest("aaaa");
        System.out.println(a);
        System.out.println(verify("aaaa", a));
    }
}
