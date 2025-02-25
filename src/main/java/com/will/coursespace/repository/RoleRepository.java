package com.will.coursespace.repository;

import com.will.coursespace.entity.Role;
import com.will.coursespace.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role,Long> {
    Optional<Role> findByName(RoleName roleName);
}
