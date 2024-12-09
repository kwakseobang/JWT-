package com.kwakmunsu.jwt.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String username;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;

    @Builder(builderClassName = "UserSaveBuilder", builderMethodName = "UserSaveBuilder")
    public User(String username, String password, String nickname, Role role) {
        this.username = username;
        this.password = password;
        // role이 null이면 기본 값으로 Role.USER 설정
        this.role = role != null ? role : Role.ADMIN;
    }

}

