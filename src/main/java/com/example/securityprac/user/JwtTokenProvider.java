package com.example.securityprac.user;

import com.example.securityprac.user.controller.TokenDto;
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

//    public TokenDto createToken(Authentication authentication){
//        return
//    }

}
