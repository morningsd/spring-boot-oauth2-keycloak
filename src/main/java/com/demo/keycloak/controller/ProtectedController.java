package com.demo.keycloak.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/protected")
public class ProtectedController {

    @GetMapping
    public String protectedEndpoint() {
        return "Hello, protected!";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_realm_user')")
    public ResponseEntity<Void> protectedUserEndpoint() {
        return ResponseEntity.ok().build();
    }
}
