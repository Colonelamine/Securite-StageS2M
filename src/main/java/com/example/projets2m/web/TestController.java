package com.example.projets2m.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/Acceuil")
public class TestController {

    @GetMapping("")
    public String Message(){
        return "Hello S2M";
    }
}
