package com.example.securityprac.config;

import com.example.securityprac.user.JwtAccessDeniedHandler;
import com.example.securityprac.user.JwtAuthenticationEntryPoint;
import com.example.securityprac.user.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;


    @Bean
    public BCryptPasswordEncoder passwordEncoder(){ // password 암호화
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // token사용시 disabled
                .formLogin().disable()
                .authorizeRequests()// HttpServletRequest를 사용하는 요청
                .antMatchers("/api/users/sign").permitAll() // 공개 경로 설정
                .antMatchers("/api/users/login").permitAll() // 공개 경로 설정
                .anyRequest().authenticated(); // 나머지 요청은 인증 필요
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .permitAll();
        return http.build();
    }
}
