import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Jjwt {

    public static void main(String[] args) throws UnsupportedEncodingException ,
            NoSuchAlgorithmException ,
            InvalidKeyException {
        //使用jjwt生成jwt
        //快速开始
//        //签名使用加密算法设置
//        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
//        //sub 可达鸭
//        String compact = Jwts.builder().setSubject("可达鸭").signWith(secretKey).compact();
//        System.out.println(compact);
//
//        //jwt解码器建造工厂 设置jwt解码器签名加密方式 建造 用此解码器验证jwt（exception则表示jwt不合法或者签名加密方式不对）
//        //获取jwt payload部分 获取subject
//        String subject = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(compact).getBody().getSubject();
//        System.out.println(subject);

        //完整步骤
        //创建JWT
        //创建Hmac-SHA算法需要的key(256位 32字节)
//        Keys.hmacShaKeyFor("123456".getBytes("UTF-8"));//直接手动创建key取其bytes 或 填入一个被加密过的byte数组
//        Keys.hmacShaKeyFor(Decoders.BASE64.decode("123456"));//手动创建key对其进行BASE64加密
        SecretKey secretKey = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode("123456781234567812345678123456781234567812345678"));//手动创建key对其进行BASE64URL加密
        String jwt = Jwts.builder() //构建Jwt建造者
                .setHeaderParam("typ", "JWT") //设置标头参数
                .claim("hello", "world") //设置索偿（payload jwt主体内容）
                .claim("name", "可达鸭")
                .signWith(secretKey, SignatureAlgorithm.HS256) //设置加密使用的密钥及加密算法（加密算法可不指定）
                .compact();
        System.out.println(jwt);
        //读取JWT
        Jws<Claims> jws = Jwts.parserBuilder() //构建JWT解析器建造者
                .setSigningKey(secretKey) //指定要解析的JWT所使用的secretKey用以判断签名是否正确 不正确代表JWT已不可信
                .build() //调用build来返回线程安全的JWT解析器
                //填入需要解析的JWT
                .parseClaimsJws("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwibmFtZSI6IuWPr-i-vum4rSJ9.T3GFPGTEBOe9dTZBZ8HKWSOa3Z9dmvVY_VhKaU_Gr48");
        System.out.println(jws);


        //手动生成jwt
//        //创建jwt标头和payload
//        String header = "{\"alg\":\"HS256\"}";
//        String claims = "{\"sub\":\"可达鸭\"}";
//        //使用基于Commons Codec的URLBase64加密header及payload
//        byte[] encodeHeaderBytes = Base64.encodeBase64URLSafe(header.getBytes());
//        byte[] encodeClaimsBytes = Base64.encodeBase64URLSafe(claims.getBytes());
//        //将字节码转为String
//        String encodeHeader = new String(encodeHeaderBytes);
//        String encodeClaims = new String(encodeClaimsBytes);
//        System.out.println("标头："+encodeHeader);
//        System.out.println("载荷："+encodeClaims);
//        //生成HmacSHA256加密的secret及message
//        String secret = "123456";
//        String message = encodeHeader + "." + encodeClaims;
//        //构建以secret作为加密盐的HmacSHA256加密器
//        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
//        SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
//        sha256_HMAC.init(secret_key);
//        //生成签名 并用BaseURL编码
//        String verifySignature = new String(Base64.encodeBase64URLSafe(sha256_HMAC.doFinal(message.getBytes())));
//        System.out.println("手动生成jwt:\n" + message + "." + verifySignature);
        //手动生成Jwt结束
//        //构建base64加密器 有误弃用 标头和payload使用的加密方式是base64Url 不是 base64
//        BASE64Encoder base64Encoder = new BASE64Encoder();
//        //base64加密头部
//        String encodeHeader = base64Encoder.encode(header.getBytes("UTF-8"));
//        String encodeCliaims = base64Encoder.encode(claims.getBytes("UTF-8"));
//        //将经过Base64加密的header和payload通过.组合到一起
//        String s = encodeHeader + "." + encodeCliaims;
//        System.out.println(s);
//        //使用HmacSha256进行签名
//        //请求的加密算法不存在则触发NoSuchAlgorithmException异常
    // 测试官网 secret base64 encode 选项功能代码
//        String secret = "123456";//普通密钥
//        Base64 base64 = new Base64();
//        byte[] secret = new Base64().encode("123456".getBytes("UTF-8"));//复杂密钥
//        System.out.println("Base64加密盐：" + new String(secret));
//        //Base64加密盐：MTIzNDU2
//
//        String message = encodeHeader + "." + encodeClaims;
//        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
//        SecretKeySpec secret_key = new SecretKeySpec(secret, "HmacSHA256");
//        sha256_HMAC.init(secret_key);
//        String verifySignature = new String(Base64.encodeBase64URLSafe(sha256_HMAC.doFinal(message.getBytes())));
//        System.out.println("Base64加密盐最终签名:" + verifySignature);
//        //Base64加密盐最终签名:V7TXJxLIij3gduj6b_8oGQ6K_RmA3kd43S8RrOB554s
//
//        secret_key = new SecretKeySpec("123456".getBytes("UTF-8"),"HmacSHA256");
//        sha256_HMAC.init(secret_key);
//        verifySignature = new String(Base64.encodeBase64URLSafe(sha256_HMAC.doFinal(message.getBytes())));
//        System.out.println("123456加密盐最终签名:" + verifySignature);
//        //123456加密盐最终签名:2AHwp9OhaBwj2uNlXTGSzyaIfym7hrA2_ubRx4E9xd4

//        System.out.println("手动生成jwt:\n"+ message+"."+ verifySignature);

//        byte[] b = sha256_HMAC.doFinal(message.getBytes());

        //jwt官网的secret base64 encode 并不是最终不用base64url编码签名 而是对盐值进行base64加密
//        byte[] bytes = sha256_HMAC.doFinal(message.getBytes());
//        System.out.println(Hex.encodeHexString(bytes));
        //有误 弃用
//        //获取HmacSHA256加密器
//        Mac sha256HMAC = Mac.getInstance("HmacSHA256");
//        //对key进行加密
//        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
//        //对key进行初始化时 key出现错误
//        //比如长度错误 未初始化 无效编码等触发InvalidKeyException异常
//        sha256HMAC.init(secretKey);
//        byte[] array = sha256HMAC.doFinal(s.getBytes("UTF-8"));
//        StringBuilder sb = new StringBuilder();
//        for (byte item : array) {
//            sb.append(Integer.toHexString((item & 0xFF) | 0x100).substring(1, 3));
//        }
//        String secret = new String(Base64.encodeBase64URLSafe(sb.toString().getBytes()));
//        System.out.println(secret);
//        String keyOver = base64Encoder.encode(s1.getBytes("UTF-8"));
//        System.out.println(keyOver);
//
//        String jwt = s + "." + keyOver;
//        System.out.println(jwt);

    }


}
