package com.demo.security.enums;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@RequiredArgsConstructor
public enum ERole {
    ADMIN,
    MODERATOR,
    USER;

    public List<GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = Arrays.stream(ERole.values())
                .toList()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(Arrays.toString(ERole.values())))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_"+ this.name()));
        return authorities.stream().toList();
    }
}
