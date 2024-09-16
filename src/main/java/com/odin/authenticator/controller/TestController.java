package com.odin.authenticator.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.odin.authenticator.dto.TestDTO;
import com.odin.authenticator.utility.EncryptionDecryption;

@RestController
public class TestController {

    @Autowired
    private EncryptionDecryption encryptionService;
    
    @PostMapping("/test")
    public String testSecuredEndpoint(HttpServletRequest req, @RequestBody TestDTO dto) throws IOException {
        String requestBody = req.getReader().lines().reduce("", String::concat);
        System.out.println("Request Body in Controller: " + requestBody);
        System.out.println("Request Body is : " + dto.getUsername());
        return "Request Body: " + requestBody;
    }


}