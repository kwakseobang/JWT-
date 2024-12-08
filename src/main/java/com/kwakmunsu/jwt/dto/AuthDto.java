package com.kwakmunsu.jwt.dto;


import com.kwakmunsu.jwt.domain.Role;
import com.kwakmunsu.jwt.domain.User;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@RequiredArgsConstructor
public class AuthDto {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @Getter
    @NoArgsConstructor
    public static class SignUpRequest {

        private String username;
        private String password;

        public User toEntity(String pw, Role role) {
            return User.UserSaveBuilder()
                    .username(this.username)
                    .password(pw)
                    .role(role)
                    .build();
        }
    }

}
