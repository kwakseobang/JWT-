package com.kwakmunsu.jwt.controller;


import com.kwakmunsu.jwt.dto.AuthDto;
import com.kwakmunsu.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class AuthController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody AuthDto.SignUpRequest signUpRequestDto) {
        userService.signup(signUpRequestDto);
        return ResponseEntity.ok().body("회원가입 성공");
    }
}
