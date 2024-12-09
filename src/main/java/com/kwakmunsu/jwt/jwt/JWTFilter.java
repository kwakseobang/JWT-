package com.kwakmunsu.jwt.jwt;
/*
스프링 시큐리티 filter chain에 요청에 담긴 JWT를 검증하기 위한 커스텀 필터를 등록해야 한다.
해당 필터를 통해 요청 헤더 Authorization 키에 JWT가 존재하는 경우 JWT를 검증하고 강제로SecurityContextHolder에 세션을 생성한다.
(이 세션은 STATLESS 상태로 관리되기 때문에 해당 요청이 끝나면 소멸 된다.)
 */

import com.kwakmunsu.jwt.domain.Role;
import com.kwakmunsu.jwt.domain.User;
import com.kwakmunsu.jwt.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

// OncePerRequestFilter -> 요청에 대해 한번만 사용? 등장?
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        // token 검증

        //request에서 Authorization 헤더를 찾음
        String authorization= request.getHeader("Authorization");

        //Authorization 헤더 검증
        // HTTP 인증 방식은 RFC 7235 정의에 따라 아래 인증 헤더 형태를 가져야 한다.
        //        Authorization: Bearer 인증토큰
        if (authorization == null || !authorization.startsWith("Bearer ")) {

            System.out.println("token null"); // 에외 처리로 바꿔야함
            filterChain.doFilter(request, response); // 종료하고 다음 필터로 넘겨줌

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        //Bearer 부분 제거 후 순수 토큰만 획득 -> 공백을 기준으로 나뉘어 리스트가 생성됨 -> 접두사(Bearer)와 토큰 분리.
        String token = authorization.split(" ")[1];

        //토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {

            System.out.println("token expired"); // 에외 처리로 바꿔야함
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }
        // token을 이용해서 일시적인 세션 생성

        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        Role role = jwtUtil.getRole(token);

        //userEntity를 생성하여 값 set
        User user = User.UserSaveBuilder()
                .username(username)
                .password("random")
                .role(role)
                .build();
        //UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(user);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);


    }
}
