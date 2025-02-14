package com.will.coursespace.repository;

import com.will.coursespace.entity.User;
import com.will.coursespace.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findByRole(Role role);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}
