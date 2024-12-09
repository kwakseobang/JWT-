package com.kwakmunsu.jwt.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value; // lombok.Value 가 아님.
import org.springframework.stereotype.Component;

/*
토큰 Payload에 저장될 정보
   - username
   - role
   - 생성일
   - 만료일
JWTUtil 구현 메소드
   - JWTUtil 생성자
   - username 확인 메소드
   - role 확인 메소드
   - 만료일 확인 메소드

 */
@Component
public class JWTUtil {

    private SecretKey secretKey; // 객체 key

    // logic - 사용자 정의해둔 암호화 키를 불러와서 그 키를 기반으로 객체 키를 만듬 string 키는 JWT에서 사용 안함.
    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {

        // 객체 변수로 암호화
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token) {
        // JWT는 paload에 사용자가 집어넣은 정보를 저장한다 했다. 그래서 payload로 가져오고 get 메서드를 통해 원하는 정보를 가져온다.
        return getPayload(token).get("username", String.class);
    }

    public String getRole(String token) {

        return getPayload(token).get("role", String.class);
    }

    // 토큰 소멸 되었는지.
    public Boolean isExpired(String token) {
        // 현재 시간으로 토큰 유효 확인.
        return getPayload(token).getExpiration().before(new Date());
    }

    // 토큰 생성 메소드  expiredMs은 token 유효 기간
    public String createJwt(String username, String role, Long expiredMs) {

        return Jwts.builder()
                .claim("username", username) // data 삽입
                .claim("role", role) // data 삽입
                .issuedAt(new Date(System.currentTimeMillis())) // 토큰이 발행한 시간을 넣어줌.
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 언제 소멸될것인지. 현재 시간 + 유효 기간.
                .signWith(secretKey) // 암호화 진행
                .compact();
    }

    public Claims getPayload(String token) {
        //
        return Jwts.parser()
                .verifyWith(secretKey) // 토큰 검증
                .build()
                .parseSignedClaims(token) //Claim 확인
                .getPayload(); // 특정한 data 가져옴
    }

}
