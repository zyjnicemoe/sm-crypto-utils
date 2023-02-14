package cn.zyjblogs.crypto.sm2;

import cn.zyjblogs.crypto.SmException;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Locale;

/**
 * 国密SM2非对称加密算法
 * @author zhuyijun
 */
public class SM2 {

    public static final String CRYPTO_NAME_SM2 = "sm2p256v1";
    public static final String BC04 = "04";
    private static final byte SM2_CIPHER_FIRST_BIT = 4;
    private static final int DEFAULT_KEY_SIZE = 128;

    public enum EncodeType {
        UTF8,
        HEX,
        BASE64
    }

    public enum Mode {
        /**
         * BC库默认排序方式-C1C2C3
         */
        CIPHER_MODE_BC,
        /**
         * 国密标准排序方式-C1C3C2
         */
       CIPHER_MODE_NORM
    }
    /**
     * 生成SM2公私钥对
     * <p>
     * BC库使用的公钥=64个字节+1个字节（04标志位），BC库使用的私钥=32个字节
     * SM2秘钥的组成部分有 私钥D,公钥X,公钥Y, 他们都可以用长度为64的16进制的HEX串表示，
     * SM2公钥并不是直接由X+Y表示, 而是额外添加了一个头,当启用压缩时:公钥=有头+公钥X,即省略了公钥Y的部分
     *
     * @param compressed 是否压缩公钥（加密解密都使用BC库才能使用压缩）
     * @return SM2 HEX字符串格式秘钥对
     */
    public static SM2KeyPair generateSm2Keys(boolean compressed) {

        // 获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
        // 构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());

        // 创建秘钥对生成器
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        // 初始化生成器,带上随机数
        keyPairGenerator.init(new ECKeyGenerationParameters(domainParameters, new SecureRandom()));
        // 生成秘钥对
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();

        // 把公钥转换为椭圆点
        ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) asymmetricCipherKeyPair.getPublic();
        ECPoint ecPoint = publicKeyParameters.getQ();

        // 把公钥转换为HEX
        // 公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04,默认压缩公钥
        String publicKey = Hex.toHexString(ecPoint.getEncoded(compressed)).toUpperCase(Locale.ROOT);

        // 把私钥转换为HEX
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        BigInteger intPrivateKey = privateKeyParameters.getD();
        String privateKey = intPrivateKey.toString(16).toUpperCase(Locale.ROOT);

        // 构造HEX秘钥对，并返回
        return new SM2KeyPair(publicKey, privateKey);
    }

    /**
     * SM2加密算法
     *
     * @param pubKey 公钥
     * @param data   待加密的数据
     * @return 密文，BC库产生的密文带由04标识符，与非BC库对接时需要去掉开头的04
     */
    public static String encrypt(String pubKey, String data) {

        // 按国密排序标准加密
        return encrypt(pubKey, data, SM2EngineExtend.CIPHER_MODE_NORM, EncodeType.UTF8, EncodeType.HEX);
    }

    /**
     * SM2加密算法
     *
     * @param pubKey 公钥
     * @param data   待加密的数据
     * @param inputType 输入数据类型
     * @param outType 输出数据类型
     * @return 密文，BC库产生的密文带由04标识符，与非BC库对接时需要去掉开头的04
     */
    public static String encrypt(String pubKey, String data,EncodeType inputType, EncodeType outType) {

        // 按国密排序标准加密
        return encrypt(pubKey, data, SM2EngineExtend.CIPHER_MODE_NORM, inputType, outType);
    }
    /**
     *  加密
     * @param pubKey 公钥
     * @param data  待加密的数据
     * @param mode 模式
     *       CIPHER_MODE_BC   BC库默认排序方式-C1C2C3
     *       CIPHER_MODE_NORM 国密标准排序方式-C1C3C2
     * @param inputType 输入数据类型
     * @param outType 输出数据类型
     * @author zhuyijun
     * @date 2023/2/14 10:18
     * @return java.lang.String
    */
    public static String encrypt(String pubKey, String data,Mode mode,EncodeType inputType, EncodeType outType) {
        return encrypt(pubKey, data,Mode.CIPHER_MODE_BC == mode ? SM2EngineExtend.CIPHER_MODE_BC : SM2EngineExtend.CIPHER_MODE_NORM, inputType, outType);
    }
    /**
     * SM2加密算法
     *
     * @param pubKey     公钥
     * @param data       待加密的数据
     * @param cipherMode 密文排列方式0-C1C2C3；1-C1C3C2；
     * @return 密文，BC库产生的密文带由04标识符，与非BC库对接时需要去掉开头的04
     */
    public static String encrypt(String pubKey, String data, int cipherMode, EncodeType inputType, EncodeType outType) {
        try {
            // 非压缩模式公钥对接放是128位HEX秘钥，需要为BC库加上“04”标记
            if (pubKey.length() == DEFAULT_KEY_SIZE) {
                pubKey = BC04 + pubKey;
            }
            // 获取一条SM2曲线参数
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
            // 构造ECC算法参数，曲线方程、椭圆曲线G点、大整数N
            ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
            //提取公钥点
            ECPoint pukPoint = sm2ECParameters.getCurve().decodePoint(Hex.decode(pubKey));
            // 公钥前面的02或者03表示是压缩公钥，04表示未压缩公钥, 04的时候，可以去掉前面的04
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, domainParameters);

            SM2EngineExtend sm2Engine = new SM2EngineExtend();
            // 设置sm2为加密模式
            sm2Engine.init(true, cipherMode, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
            byte[] in;
            if (EncodeType.HEX.equals(inputType)) {
                in = Hex.decode(data);
            } else if (EncodeType.BASE64.equals(inputType)) {
                in = Base64.getDecoder().decode(data.getBytes(StandardCharsets.UTF_8));
            } else {
                in = data.getBytes(StandardCharsets.UTF_8);
            }
            byte[] arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
            if (EncodeType.BASE64.equals(outType)) {
                byte[] base64Bytes = Base64.getEncoder().encode(arrayOfBytes);
                return new String(base64Bytes, StandardCharsets.UTF_8);
            } else if (EncodeType.HEX.equals(outType)) {
                return Hex.toHexString(arrayOfBytes).toUpperCase(Locale.ROOT);
            } else {
                return new String(arrayOfBytes, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            throw new SmException(e);
        }

    }

    private static byte[] addBitIfNeed(byte[] base64Decode) {
        byte first = base64Decode[0];
        if (first == SM2_CIPHER_FIRST_BIT) {
            return base64Decode;
        } else {
            byte[] finalByte = new byte[base64Decode.length + 1];
            finalByte[0] = SM2_CIPHER_FIRST_BIT;
            System.arraycopy(base64Decode, 0, finalByte, 1, base64Decode.length);
            return finalByte;
        }
    }

    /**
     * SM2解密算法
     *
     * @param priKey     私钥
     * @param cipherData 密文数据
     * @return 解密后的数据
     */
    public static String decrypt(String priKey, String cipherData) {
        // // 按国密排序标准解密
        return decrypt(priKey, cipherData, SM2EngineExtend.CIPHER_MODE_NORM, EncodeType.HEX, EncodeType.UTF8);
    }

    /**
     * 解密
     * @param priKey  私钥
     * @param cipherData 密文数据
     * @param inputType 输入数据类型
     * @param outType 输出数据类型
     * @author zhuyijun
     * @date 2023/2/14 10:11
     * @return java.lang.String
    */
    public static String decrypt(String priKey, String cipherData,EncodeType inputType, EncodeType outType) {
        // // 按国密排序标准解密
        return decrypt(priKey, cipherData, SM2EngineExtend.CIPHER_MODE_NORM, inputType, outType);
    }

    /**
     * SM2解密算法
     *
     * @param priKey     私钥
     * @param cipherData 密文数据
     * @param cipherMode 密文排列方式 0-C1C2C3；1-C1C3C2；
     * @return 解密后的数据
     */
    public static String decrypt(String priKey, String cipherData, int cipherMode, EncodeType inputType, EncodeType outType) {

        try {
            byte[] cipherDataByte;
            if (EncodeType.HEX.equals(inputType)) {
                // 使用BC库加解密时密文以04开头，传入的密文前面没有04则补上
                if (!cipherData.startsWith(BC04)) {
                    cipherData = BC04 + cipherData;
                }
                cipherDataByte = Hex.decode(cipherData);
            } else if (EncodeType.BASE64.equals(inputType)) {
                cipherDataByte = Base64.getDecoder().decode(cipherData);
                cipherDataByte = addBitIfNeed(cipherDataByte);
            } else {
                cipherDataByte = cipherData.getBytes(StandardCharsets.UTF_8);
            }
            //获取一条SM2曲线参数
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
            //构造domain参数
            ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());

            BigInteger privateKeyD = new BigInteger(priKey, 16);
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyD, domainParameters);

            SM2EngineExtend sm2Engine = new SM2EngineExtend();
            // 设置sm2为解密模式
            sm2Engine.init(false, cipherMode, privateKeyParameters);

            byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
            if (EncodeType.HEX.equals(outType)) {
                return Hex.toHexString(arrayOfBytes).toUpperCase(Locale.ROOT);
            } else if (EncodeType.BASE64.equals(outType)) {
                byte[] base64Bytes = Base64.getEncoder().encode(arrayOfBytes);
                return new String(base64Bytes, StandardCharsets.UTF_8);
            } else {
                return new String(arrayOfBytes, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            throw new SmException(e);
        }

    }

    /**
     * 签名
     *
     * @param priKey    私钥
     * @param plainText 待签名文本
     * @return 签名
     */
    public static String sign(String priKey, String plainText) {

        try {
            // 构造提供器
            BouncyCastleProvider provider = new BouncyCastleProvider();
            // 获取一条SM2曲线参数
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
            // 构造椭圆参数规格
            ECParameterSpec ecParameterSpec = new ECParameterSpec(sm2ECParameters.getCurve(),
                    sm2ECParameters.getG(), sm2ECParameters.getN(), sm2ECParameters.getH());
            // 创建Key工厂
            KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);

            // 创建签名对象
            Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), provider);

            // 将私钥HEX字符串转换为X值
            BigInteger bigInteger = new BigInteger(priKey, 16);
            // 生成SM2私钥
            BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) keyFactory.generatePrivate(new ECPrivateKeySpec(bigInteger,
                    ecParameterSpec));

            // 初始化为签名状态
            signature.initSign(bcecPrivateKey);
            // 传入签名字节
            signature.update(plainText.getBytes());

            // 签名
            return Hex.toHexString(signature.sign()).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new SmException(e);
        }

    }

    /**
     * 验签
     *
     * @param pubKey         公钥
     * @param plainText      明文
     * @param signatureValue 签名
     * @return 验签结果
     */
    public static boolean verify(String pubKey, String plainText, String signatureValue) {

        // 非压缩模式公钥对接放是128位HEX秘钥，需要为BC库加上“04”标记
        if (pubKey.length() == DEFAULT_KEY_SIZE) {
            pubKey = BC04 + pubKey;
        }

        try {
            // 构造提供器
            BouncyCastleProvider provider = new BouncyCastleProvider();

            // 获取一条SM2曲线参数
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CRYPTO_NAME_SM2);
            // 构造椭圆参数规格
            ECParameterSpec ecParameterSpec = new ECParameterSpec(sm2ECParameters.getCurve(),
                    sm2ECParameters.getG(), sm2ECParameters.getN(), sm2ECParameters.getH());
            // 创建Key工厂
            KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);

            // 创建签名对象
            Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), provider);

            // 将公钥HEX字符串转换为椭圆曲线对应的点
            ECPoint ecPoint = sm2ECParameters.getCurve().decodePoint(Hex.decode(pubKey));
            BCECPublicKey bcecPublicKey = (BCECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(ecPoint, ecParameterSpec));

            // 初始化为验签状态
            signature.initVerify(bcecPublicKey);
            signature.update(plainText.getBytes());

            return signature.verify(Hex.decode(signatureValue));
        } catch (Exception e) {
            throw new SmException(e);
        }

    }

    /**
     * 证书验签
     *
     * @param certStr      证书串
     * @param plaintext    签名原文
     * @param signValueStr 签名产生签名值 此处的签名值实际上就是 R和S的sequence
     * @return 证书验证结果
     */
    public static boolean certVerify(String certStr, String plaintext, String signValueStr) {
        try {
            // 构造提供器
            BouncyCastleProvider provider = new BouncyCastleProvider();
            // 解析证书
            byte[] signValue = Hex.decode(signValueStr);
            CertificateFactory factory = new CertificateFactory();
            X509Certificate certificate = (X509Certificate) factory
                    .engineGenerateCertificate(new ByteArrayInputStream(Hex.decode(certStr)));
            // 验证签名
            Signature signature = Signature.getInstance(certificate.getSigAlgName(), provider);
            signature.initVerify(certificate);
            signature.update(plaintext.getBytes());

            return signature.verify(signValue);
        } catch (Exception e) {
            throw new SmException(e);
        }

    }

    public static void main(String[] args) {
        String data = "dPhq2XdoMcgD5m7M0I51SX7MkzMerWMcPdBdv/tX8B5jOyM28n+CcXUn721/9N0ELVgC2P0eBRn4jD04rPScJd5izcC7+xXT5LUwbV2S6wc0g2RC8nkuZITc4rdrACPvNxd18b6y";
        String pub = "0417f347d7fa08ae6ad9bf8ef6ac6c313810e05044290f7c18dc9b913b252603505cf7cdbf7ac7d88de508e78bbc2d74cb28c0a90724ed4b751cc69bdfe55b68de";
        String pri = "73d76cf4f553535d6ec45478fb1581baa0c83e166b347af10ab129966d3f187f";
        try {
            String decrypt2 = SM2.decrypt(pri, "BCWhJJ0BFPt/RuhS37sk22/5GuemkzG7kt+CLwRSz34taiKPjc0TDoY959dCf7C2cZJ2uzLoqRmcH/pV7uWGhPzTIZmKM8wPpVIeuN616dNVm+5/YpaQfcawis6KpJOeeU4fcyrYf9wcawtkow==", 1, EncodeType.BASE64, EncodeType.UTF8);
            System.out.println("-------------");
            System.out.println(decrypt2);
            String encrypt1 = SM2.encrypt(pub, decrypt2);
            System.out.println("-------------");
            System.out.println(encrypt1);
            String decrypt3 = SM2.decrypt(pri, encrypt1);
            System.out.println("aaa:" + decrypt3);
            String decrypt4 = SM2.encrypt(pub, decrypt3, 1, EncodeType.UTF8, EncodeType.BASE64);
            System.out.println(decrypt4);
            System.out.println("-----------");
            String decrypt5 = SM2.decrypt(pri, decrypt4, 1, EncodeType.BASE64, EncodeType.BASE64);
            System.out.println(decrypt5);
            String decrypt5_1 = SM2.encrypt(pub, decrypt5, 1, EncodeType.BASE64, EncodeType.BASE64);
            System.out.println(decrypt5_1);
            String decrypt5_2 = SM2.decrypt(pri, decrypt5_1, 1, EncodeType.BASE64, EncodeType.BASE64);
            System.out.println(decrypt5_2);
            System.out.println(new String(Base64.getDecoder().decode(decrypt5)));
            String decrypt6 = SM2.encrypt(pub, decrypt5, 1, EncodeType.BASE64, EncodeType.HEX);
            System.out.println(decrypt6);
            System.out.println("-----------");
            String decrypt7 = SM2.decrypt(pri, decrypt6, 1, EncodeType.HEX, EncodeType.UTF8);
            System.out.println(decrypt7);
            String decrypt8 = SM2.decrypt(pri, data, 1, EncodeType.BASE64, EncodeType.UTF8);
            System.out.println(decrypt8);
            String datanew = "BPCv4lM/sVXzEJ7uFkXrvuKUVFS3EU9uCkV9vhgJQb92cY3FWfIa1M1UtYxkbfleEdiZHZooh5DV3HaakkYsCTbR/lKF4FC3ZplGGf9rCbCuovf7fFf5TJwX2m83qkNMTuW4o9QdjOQu4MiFtYbTMMTSb/0kNKHkrT8mCSY+6yLg7XIHmzepoGiWhQ2KB9diF066YzjKNDGbP3u9/zoQBCFKr190G7F6NH042kfLPRrpV3IkewJbNKGCCQ0SIvNJ475beYq5jpRbug2WOsR8qLEsPsIl7SPXh0ezB1hLwgmqFqM/B3QbobKP+lFmtbjjIumLgdGM9OzmG82TFZM3k0piIYQPS6JPHjR3nqrnxpwYxn2bKUifnrrrM8smyoa99BzJ4IPnZ7/3oxLwkRFnMee8oyMy1WCab0k5OKmAM/dk2weflyhXyY5mxGYHjdjpsj9ipOcKjqF6LKobMxSAOpn+pRfywvJr/CKE1dcq7k1gK/xZozQVqyENoM3BEyVEYfEUHrI1pxG8/2ugYYXIN4jX6XqR8COxnJOS8XuPi8Ukqsx/E3EwgWEbI3PvtRRaiI4RNWyc1oMyNDr8Al5caf67cUo2pasoF8IrUlZtePBEAmITHfzVm9sCfGz4eNw5b2a5YSLofCYX7R6C0b/+69uutyhmLb3Na9TOyseTEYJcf0pzO8DHdWZDTldH8+swARdulURCBR3AMs2ePDnfJwMcEyNt1jpacVDSRPIVhxOcgdeD3juaYpiEYdVTPBHv+RJoOi6pv87ZheeDejjpGUMLAGEC/P+SpGdG8IT7THEPw16/hNK/lzqAzmYa7lkAH2WycWbnaBed3bHJbJBNjP9DsBpAf3V/PGreXNWeD66g+gCQDhyOUdiWqoaEoCLA7nkOcQqEeDZNegQn5ZfU/cW4yW1sxfb3CNzqxJaA/qayon+BeCYmy3FpA0SIkAbA0/qTG7VWg4u4kAQBG+FZ+lJ9Eaj9JaFiCgqfQRBMEoLuVdH24UeRljIfRptuYDcPydCFRzDWhYqwguPeGluEb9JO8eESZ+waX48xtniMvxbQ0CzfDlMWJwO9EiPJyIj2b86/ibBfSq9vuWwSdeLLL2Jvjn5LB9cwzSU8yQzLgle9YGSC0sbQIMuyFHUhDUVyFTVPE3/bYpotuetoeQVMYvLe9H73825Q6PxY+CCMHb0Jqjva2JAf6emYGx1vb5MGoJzoxz/7lSxJ56I9yMfrwLMljToMSufcV+bhQYb6r468qtQ10eXlKom/I8ZqZIJHsIaZBxsxJe1UyxqGitasg55gqNLLDwv+6UmnvGT/B6g9bmfc363/gO5mQlJfZSlpUodZrXMCYZmNI1ZZFRQbu5aEdtL9M2lXeCnTJa2GDOqpbG5I3aWVcepUcCsx4375bJOo3g24dwhzTCyh7/dW9sPhqb3SSXb/l+JxFzUoBXzxQgpBzakwq1uGrCKYPkNfYrmxRej87ZGgQFGlCVjEUHwRhvnkLHTXeP2f3b8zCeu+6us=";
            String decrypt9 = SM2.decrypt(pri, datanew, 1, EncodeType.BASE64, EncodeType.UTF8);
            System.out.println(decrypt9);
            SM2KeyPair sm2KeyPair = generateSm2Keys(true);
            System.out.println("公钥\n" + sm2KeyPair.getPublicKey());
            System.out.println("私钥\n" + sm2KeyPair.getPrivateKey());
            String a = SM2.encrypt(sm2KeyPair.getPublicKey(), "好吃啊");
            System.out.println(a);
            System.out.println(SM2.decrypt(sm2KeyPair.getPrivateKey(), a));
            String data1 = "c4eba3e104f1858a4ad0eeea125537e80ad28d10e6b084c26a1c318dba4bec334bf246cdd3900bc35e20a2c8bf6948a050f5c9077b0617db7d98489c37f3cc8aebebf98a39c0f127e6d37a8ec31f3968f07c7a01b8d3e1a554d53b75de8ede6d50050d8a1c60e976e74829b0f32bc049edf7";
            System.out.println(SM2.decrypt("69A124C827FA42573FF1047368BA8428C04A04B5B947BBD202956CF1A78D1FB0", data1, 1, EncodeType.HEX, EncodeType.UTF8));
            String sign = SM2.sign("69A124C827FA42573FF1047368BA8428C04A04B5B947BBD202956CF1A78D1FB0", data1);
            System.out.println("私钥签名:\n" + sign);
            System.out.println(SM2.verify("032AB168CD73ED25824DB20B5F190C7C54971BC821450DEE0AC84C779CF3A9F897", data1, sign));
            String base64 = "BTcOfUO9+YxUeVl3nAkrebsu7H1scPwAppe0slpHLSMa4+2GhvW4ZTr++8AFT5pND3rcLtU76bzoIencvojqhvV8drMjGA6yPbp+6dg/KABNcE0SRwHhzNcTrf5SxTC4yI1TIuvo";
            String decrypt10 = SM2.decrypt(pri, base64, 1, EncodeType.BASE64, EncodeType.UTF8);
            System.out.println(decrypt10);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
