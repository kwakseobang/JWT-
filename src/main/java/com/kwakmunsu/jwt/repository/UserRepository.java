package com.kwakmunsu.jwt.repository;


import com.kwakmunsu.jwt.domain.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Long> {

        Optional<User>findByUsername(String username);

}