package com.kwakmunsu.jwt.service;

import com.kwakmunsu.jwt.domain.Role;
import com.kwakmunsu.jwt.domain.User;
import com.kwakmunsu.jwt.dto.AuthDto.SignUpRequest;
import com.kwakmunsu.jwt.repository.UserRepository;
import com.sun.jdi.request.DuplicateRequestException;
import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @Transactional
    public void signup(SignUpRequest signUpRequestDto) {
        // 중복 체크
        String username = signUpRequestDto.getUsername();
        userRepository.findByUsername(username)
                .ifPresent(user -> {throw new DuplicateRequestException("중복: " + username);
                });
        User user = signUpRequestDto.toEntity(bCryptPasswordEncoder.encode(
                signUpRequestDto.getPassword()), Role.ADMIN);

        userRepository.save(user);
    }
}
