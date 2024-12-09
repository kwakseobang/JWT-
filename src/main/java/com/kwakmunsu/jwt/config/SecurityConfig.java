package com.kwakmunsu.jwt.config;


import com.kwakmunsu.jwt.jwt.JWTFilter;
import com.kwakmunsu.jwt.jwt.JWTUtil;
import com.kwakmunsu.jwt.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil; // LoginFilter -> 의존성 주입
    // 암호화
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    //AuthenticationManager Bean -> 등록 후 filter에 주입
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disable - session을 stateless 상태로 두기때문에 비활성화
        http
                .csrf((auth) -> auth.disable());

        //From 로그인 방식 disable - jwt를 사용하기때문에
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable  - jwt를 사용하기때문에
        http
                .httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/signup").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        // JWT filter 등록
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        // Loginfilter 등록
        http
                .addFilterAt(new LoginFilter(
                                authenticationManager(authenticationConfiguration),
                                jwtUtil
                        ), UsernamePasswordAuthenticationFilter.class);



        // JWT를 통한 인증/인가를 위해서 세션을 STATELESS 상태로 설정하는 것이 중요하다.
        // 세션 설정 stateless로 설정해야됨
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}
