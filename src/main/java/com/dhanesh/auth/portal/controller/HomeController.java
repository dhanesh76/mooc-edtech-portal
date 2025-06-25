package com.dhanesh.auth.portal.controller;

import org.springframework.web.bind.annotation.RestController;

import com.dhanesh.auth.portal.entity.Users;
import com.dhanesh.auth.portal.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;


@RestController
@RequiredArgsConstructor
public class HomeController {
    
    private final UserRepository userRepo;
    
    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/courses")
    public String courses() {
        return "courses";   
    }

    @GetMapping("/users/all")
    ResponseEntity<List<Users>> users(){
        return ResponseEntity.ok().body(userRepo.findAll());
    }
}
