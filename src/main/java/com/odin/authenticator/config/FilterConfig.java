package com.odin.authenticator.config;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.support.StandardServletMultipartResolver;
import org.springframework.web.reactive.function.client.WebClient;

import com.odin.authenticator.filters.CustomFilter;

import reactor.netty.http.client.HttpClient;

@Configuration
public class FilterConfig {

    @Value("${bypass.apis}")
    private String bypassApis;

    @Value("${encryption.key}")
    private String encryptionKey;
    
    @Bean
    public FilterRegistrationBean<CustomFilter> customFilterRegistration(CustomFilter customFilter) {
        FilterRegistrationBean<CustomFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(customFilter);
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);
        return registrationBean;
    }
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    
//    @Bean
//    public WebClient webClient(WebClient.Builder webClientBuilder) {
//        // Configure the HttpClient for WebClient with custom timeouts
//        HttpClient httpClient = HttpClient.create()
//                .responseTimeout(Duration.ofSeconds(30))  // Set response timeout (for waiting for a response)
//                .option(io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS, 30000);  // Set connection timeout (for establishing a connection)
//
//        return webClientBuilder
//                .clientConnector(new ReactorClientHttpConnector(httpClient)) // Use the customized HttpClient
//                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(10 * 1024 * 1024)) // 10MB buffer
//                .build();
//    }
    
    @Bean
    public MultipartResolver multipartResolver() {
        return new StandardServletMultipartResolver();
    }


}
