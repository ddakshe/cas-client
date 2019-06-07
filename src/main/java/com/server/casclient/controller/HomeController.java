package com.server.casclient.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @Value("${server.port}")
    String port;


    @GetMapping("/")
    public String home(){
        return "home:"+port;
    }
}
