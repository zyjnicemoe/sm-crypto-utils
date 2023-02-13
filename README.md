# sm-crypto-utils
用于国密SM2、SM3、SM4的加解密工具,基于BC库实现
## 您可以再Maven项目中引用
```xml
<dependency>
  <groupId>cn.zyjblogs</groupId>
  <artifactId>sm-crypto-utils</artifactId>
  <version>1.0.1</version>
</dependency>
```
## 您可以使用它
-  国密SM2算法
```java
public class test {
public static void main(String[] args) {
        String data = "dPhq2XdoMcgD5m7M0I51SX7MkzMerWMcPdBdv/tX8B5jOyM28n+CcXUn721/9N0ELVgC2P0eBRn4jD04rPScJd5izcC7+xXT5LUwbV2S6wc0g2RC8nkuZITc4rdrACPvNxd18b6y";
        String pub = "0417f347d7fa08ae6ad9bf8ef6ac6c313810e05044290f7c18dc9b913b252603505cf7cdbf7ac7d88de508e78bbc2d74cb28c0a90724ed4b751cc69bdfe55b68de";
        String pri = "73d76cf4f553535d6ec45478fb1581baa0c83e166b347af10ab129966d3f187f";
        String key = "0123456789abcdeffedcba9876543210";
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
```
-  国密SM3算法
```java
public class test {
    public static void main(String[] args) {
        String a = SM3.digest("sm3");
        System.out.println(a);
        System.out.println(verify("sm3", a));
    }
}
```
- 国密SM4算法使用
```java
public class test {
    public static void main(String[] args) {
        String iv = SM4.generateKey();
        System.out.println(iv);
        System.out.println("加密:---------");
        String v = SM4.encrypt(iv, "晚日照空矶，采莲承晚晖。\n" +
                "                风起湖难渡，莲多采未稀。\n" +
                "                棹动芙蓉落，船移白鹭飞。\n" +
                "                荷丝傍绕腕，菱角远牵衣。", iv);
        System.out.println(v);
        String digest = SM3.digest(v);
        System.out.println(digest);
        System.out.println("解密:---------");
        System.out.println(SM4.decrypt(iv, v, iv));
        System.out.println("解密:---------");
        System.out.println(SM4.decrypt("864669EB9E57E15C923E1003CBEA8872", "6a05d74bda1f2a41c0b47605b06ef638", "fedcba98765432100123456789abcdef"));
    }
}
```