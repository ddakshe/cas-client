package com.server.casclient.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredController {

    @Value("${server.port}")
    String port;


    @GetMapping("/secured")
    public Authentication secured() {
        Authentication auth = SecurityContextHolder.getContext()
                .getAuthentication();
        return auth;
    }
}
