package com.demo.security.Controller;

import com.demo.security.models.AuthenticationRequest;
import com.demo.security.models.AuthenticationResponse;
import com.demo.security.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticateResource {
    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody AuthenticationRequest request) {
        AuthenticationRequest user = AuthenticationRequest.builder()
                .email(request.getEmail())
                .password(request.getPassword())
                .build();
       return authenticationService.authenticate(user).getAccessToken();
    }

    @PostMapping("/refresh-token")
    public AuthenticationResponse refreshToken(HttpServletRequest request) throws UsernameNotFoundException {
        return authenticationService.refreshToken(request)
                .orElseThrow(() -> new UsernameNotFoundException("Username not found"));
    }

    @PostMapping("/register")
    public AuthenticationResponse register(@RequestBody AuthenticationRequest request) throws UsernameNotFoundException {
        return authenticationService.register(request);
    }

}
