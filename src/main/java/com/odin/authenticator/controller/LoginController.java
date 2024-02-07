package com.odin.authenticator.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

import com.odin.authenticator.constants.ApplicationConstants;

@Slf4j
@CrossOrigin(origins = "*")
@RestController
@RequestMapping(value = ApplicationConstants.API_VERSION)
public class LoginController {

	
	@PostMapping(value = ApplicationConstants.LOGIN)
	public ResponseEntity<Object> apiMetadataController(HttpServletRequest request){
		log.info("Inside API info controller");
		return null;
	}
}
