package com.kwakmunsu.jwt.service;

import com.kwakmunsu.jwt.domain.User;
import com.kwakmunsu.jwt.repository.UserRepository;
import jakarta.transaction.Transactional;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUSerDetailService implements UserDetailsService {

    private final UserRepository userRepository;


    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return userRepository.findByUsername(username)
                .map(this::createUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException("not Found"));
    }
    private UserDetails createUserDetails(User user) {
        // Spring Security는 내부적으로 사용자의 권한을 GrantedAuthority 객체로 관리합니다.
        //user.getRole()이 반환하는 값이 단순 문자열이라면, 이를 Spring Security가 인식하지 못합니다.
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(user.getRole().toString());

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.singleton(grantedAuthority) // 단일 권한
        );
    }
}
