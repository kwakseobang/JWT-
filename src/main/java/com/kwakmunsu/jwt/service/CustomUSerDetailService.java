package com.kwakmunsu.jwt.service;

import com.kwakmunsu.jwt.domain.User;
import com.kwakmunsu.jwt.dto.CustomUserDetails;
import com.kwakmunsu.jwt.repository.UserRepository;
import jakarta.transaction.Transactional;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
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

        // 사용자 조회
        User userData = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // CustomUserDetails로 반환
        return new CustomUserDetails(userData);
    }


}
