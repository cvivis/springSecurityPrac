package com.example.securityprac.user;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.io.Decoders;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider implements InitializingBean {
    //JWT 토큰의 생성, 검증 및 처리를 관리하는 클래스입니다.
    // Spring Security와 함께 사용되며, 토큰 생성, 검증, 유효성 확인 등의 작업을 처리합니다.

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-expired}")
    private Long accessExpired;

    @Value("${jwt.refresh-expired}")
    private Long refreshExpired;

    private Key signKey;

    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.signKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public TokenDto createToken(String email, String authorities) {
        Long now = System.currentTimeMillis();

        String accessToken = Jwts.builder()
                .setHeaderParam("typ","JWT")
                .setHeaderParam("alg","HS512")
                .setExpiration(new Date(now + accessTokenExpirationTime))
                .setSubject("access-token")
                .claim(emailClaim,email)
                .claim("authority",authorities)
                .setIssuedAt(new Date(now))
                .signWith(signingKey, SignatureAlgorithm.HS512)
                .compact();

        String refreshToken = Jwts.builder()
                .setHeaderParam("typ","JWT")
                .setHeaderParam("alg","HS512")
                .setExpiration(new Date(now + refreshTokenExpirationTime))
                .setSubject("refresh-token")
                .setIssuedAt(new Date(now))
                .signWith(signingKey, SignatureAlgorithm.HS512)
                .compact();
        return new TokenDto(accessToken, refreshToken);
    }

    public Claims getClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch( ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public Authentication getAuthentication(String token) {
        String email = getClaims(token).get(emailClaim).toString();
        UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(email);
        return new UsernamePasswordAuthenticationToken(userDetails,"",userDetails.getAuthorities());
    }

    public long getTokenExpirationTime(String token) {
        return getClaims(token).getExpiration().getTime();
    }

//    public boolean validateJwtToken(String jwtToken) {
//        try{
//            Jwts.parserBuilder()
//                    .setSigningKey(signingKey)
//                    .build()
//                    .parseClaimsJws(jwtToken);
//            return true;
//        } catch(Exception e) {
//            //ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException;
//            log.error("[JwtTokenProvider validateRefreshToken] jwt 토큰 인증 실패, error : {}",e.getMessage());
//        }
//        return false;
//    }

    public boolean validateRefreshToken(String refreshToken){
        try {
            Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(refreshToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature.");
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty.");
        } catch (NullPointerException e){
            log.error("JWT Token is empty.");
        }
        return false;
    }

    public boolean validateAccessToken(String accessToken) {
        try {
            if (redisService.getValue(accessToken) != null // NPE 방지
                    && redisService.getValue(accessToken).equals("logout")) { // 로그아웃 했을 경우
                return false;
            }
            Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(accessToken);
            return true;
        } catch(ExpiredJwtException e) {
            log.info("[JwtTokenProvide validateAccessToken] ExpiredJwtException : {}",e.getMessage());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //access token 기한 지났으면 true, 아직 남아있으면 false
    public boolean validateAccessTokenExpired(String accessToken) {
        try {
            return getClaims(accessToken)
                    .getExpiration()
                    .before(new Date());
        } catch(ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
