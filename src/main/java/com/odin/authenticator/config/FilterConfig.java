package com.odin.authenticator.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.odin.authenticator.filters.CustomFilter;
import com.odin.authenticator.utility.EncryptionDecryption;

@Configuration
public class FilterConfig {

    @Value("${bypass.apis}")
    private String bypassApis;

    @Value("${encryption.key}")
    private String encryptionKey;
    

    // Optional: If you need to set filter order
    @Bean
    public FilterRegistrationBean<CustomFilter> customFilterRegistration(CustomFilter customFilter) {
        FilterRegistrationBean<CustomFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(customFilter);
        registrationBean.addUrlPatterns("/*");  // Adjust the pattern as per your use case
        registrationBean.setOrder(1);  // Set order of execution
        return registrationBean;
    }
}
