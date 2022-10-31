// 	<dependency>
// 			<groupId>com.auth0</groupId>
// 			<artifactId>java-jwt</artifactId>
// 			<version>3.10.3</version>
// 		</dependency>
public class JWTtest{

// 利用hutool创建RSA
static RSA rsa = new RSA();
/**
 * 生成token
 * @param payload token携带的信息
 * @return token字符串
 */
public static String getTokenRsa(Map<String,String> payload){
    // 指定token过期时间为7天
    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.DATE, 7);

    JWTCreator.Builder builder = JWT.create();
    // 构建payload
    payload.forEach((k,v) -> builder.withClaim(k,v));

    // 获取私钥
    RSAPrivateKey privateKey = (RSAPrivateKey) rsa.getPrivateKey();
    // 签名时传入私钥
    String token = builder.withExpiresAt(calendar.getTime()).sign(Algorithm.RSA256(null, privateKey));
    return token;
}

/**
 * 解析token
 * @param token token字符串
 * @return 解析后的token
 */
public static DecodedJWT decodeRsa(String token){
    // 利用hutool创建RSA
    // 获取RSA公钥
    RSAPublicKey publicKey = (RSAPublicKey) rsa.getPublicKey();
    // 验签时传入公钥
    JWTVerifier jwtVerifier = JWT.require(Algorithm.RSA256(publicKey, null)).build();
    DecodedJWT decodedJWT = jwtVerifier.verify(token);
    return decodedJWT;
}

@Test
public void testToken() {
    HashMap<String, String> map = Maps.newHashMap();
    map.put("name","libai");
    map.put("age","11");
    String tokenRsa = getTokenRsa(map);
    System.out.println(tokenRsa);
    DecodedJWT decodedJWT = decodeRsa(tokenRsa);
    System.out.println(decodedJWT);
}
}
