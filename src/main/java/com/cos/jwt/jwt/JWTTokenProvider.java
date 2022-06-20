package com.cos.jwt.jwt;

import com.cos.jwt.PemReader;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.*;

@Component
@Log4j2
@RequiredArgsConstructor
public class JWTTokenProvider {


    @Value("${application.jwt.privateKey}")
    private String jwtPrivateKey;
    private PrivateKey tokenKey;

    // 토큰 유효시간 30분
    private final long tokenValidTime = 60 * 30  * 1000L;


    // 의존성 주입 시점에 객체 초기화, secretKey를 Base64로 인코딩한다.
    @PostConstruct
    protected void init() throws IOException, GeneralSecurityException {
        // 30분 단위로 갱신되는 토큰 값.
        Path path = Paths.get(jwtPrivateKey);
        List<String> reads = Files.readAllLines(path);
        String read = "";
        for (String str : reads){
            read += str+"\n";
        }
        tokenKey = PemReader.getPrivateKeyFromString(read);
    }

    // JWT 토큰 생성
    public String createToken(String userPk, Collection<?> roles) {
        Claims claims = Jwts.claims().setSubject(userPk); // JWT payload 에 저장되는 정보단위
        claims.put("roles", roles); // 정보는 key / value 쌍으로 저장된다.
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "RS256");
        header.put("typ", "Authorization");
        Date now = new Date();
        return Jwts.builder()
                .setHeader(header) // 알고리즘과 토큰 타입을 헤더에 넣어줌
                .setClaims(claims) // 유저의 이름(userPk)등이 담겨있음
                .setIssuedAt(now) // 토큰 발행 시간 정보 iat
                .setExpiration(new Date(now.getTime() + tokenValidTime)) // set Expire Time 언제까지 유효한지.
                .signWith(SignatureAlgorithm.RS256, tokenKey)  // 사용할 암호화 알고리즘과
                .setIssuer("dev_koo")
                .setId("eroum")
                // signature 에 들어갈 secret값 세팅
                .compact();
    }

    // 토큰에서 회원 정보 추출
    public String getUserPk(String token) {
        Claims claims = Jwts.parser().setSigningKey(tokenKey).parseClaimsJws(token).getBody();
        log.info("토큰값 : '{}'", token);
        log.info(claims.getIssuedAt());
        log.info(claims.getExpiration());
        return Jwts.parser().setSigningKey(tokenKey).parseClaimsJws(token).getBody().getSubject();
    }

    // Request의 Header에서 token 값을 가져옵니다. "Authorization" : "TOKEN값'
    public String resolveToken(HttpServletRequest request) {
        String jwtToken = request.getHeader("Authorization").replace("Bearer ","");//이렇게하면 jWT만 추출되게 파싱할수 있다.
        return jwtToken;
    }

    // 만료일자 확인
    public boolean validateToken(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(tokenKey).parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}
