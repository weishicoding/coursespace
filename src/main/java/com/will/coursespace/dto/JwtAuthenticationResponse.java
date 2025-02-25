package com.will.coursespace.dto;


import com.will.coursespace.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtAuthenticationResponse {

    private String accessToken;

    private String username;

    private Set<Role> roles;
}
