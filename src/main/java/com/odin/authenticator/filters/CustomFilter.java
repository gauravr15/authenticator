package com.odin.authenticator.filters;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.odin.authenticator.constants.ApplicationConstants;
import com.odin.authenticator.service.ApiGatewayService;
import com.odin.authenticator.utility.CustomHttpRequestWrapper;
import com.odin.authenticator.utility.EncryptionDecryption;

@Component
public class CustomFilter implements Filter {

    private final EncryptionDecryption encryptionService;
    private final ObjectMapper objectMapper;
    private final ApiGatewayService apiGatewayService;  // Use the new ApiGatewayService

    @Value("${is.encryption.enabled:true}")
    private boolean isEncryptionEnabled;

    @Value("${bypass.apis}")
    private List<String> bypassApis;

    public CustomFilter(EncryptionDecryption encryptionService, ObjectMapper objectMapper, ApiGatewayService apiGatewayService) {
        this.encryptionService = encryptionService;
        this.objectMapper = objectMapper;
        this.apiGatewayService = apiGatewayService;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String requestTimestamp = httpRequest.getHeader("requestTimestamp");
        String requestURI = httpRequest.getRequestURI();
        String requestBody = null;

        // If encryption is disabled or the API is bypassed, proceed with URL transformation and REST call
        if (!isEncryptionEnabled || bypassApis.contains(requestURI.replace(ApplicationConstants.CONTEXT_PATH, ""))) {
            try {
                requestBody = httpRequest.getMethod().equalsIgnoreCase("GET") ? null : readRequestBody(httpRequest);
                String backendResponse = apiGatewayService.processAndForwardRequest(httpRequest, requestBody);
                httpResponse.getWriter().write(backendResponse);
            } catch (Exception e) {
                httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                httpResponse.getWriter().write("Error processing request: " + e.getMessage());
            }
            return;
        }

        // Handle decryption
        if (requestTimestamp == null) {
            httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            httpResponse.getWriter().write("Missing requestTimestamp header");
            return;
        }

        if ("GET".equalsIgnoreCase(httpRequest.getMethod()) || httpRequest.getContentLength() == 0) {
            chain.doFilter(request, response);
            return;
        }

        CustomHttpRequestWrapper wrappedRequest;
        if (!(httpRequest instanceof CustomHttpRequestWrapper)) {
            String body = readRequestBody(httpRequest);
            Map<String, Object> requestMap = objectMapper.readValue(body, Map.class);
            String encryptedRequest = (String) requestMap.get("request");

            if (encryptedRequest == null) {
                httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                httpResponse.getWriter().write("Missing 'request' field in JSON");
                return;
            }

            String decryptedJson;
            try {
                decryptedJson = encryptionService.decrypt(encryptedRequest, requestTimestamp);
            } catch (Exception e) {
                httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                httpResponse.getWriter().write("Error decrypting data");
                return;
            }

            wrappedRequest = new CustomHttpRequestWrapper(httpRequest, decryptedJson);
        } else {
            wrappedRequest = (CustomHttpRequestWrapper) httpRequest;
        }

        // After decryption, always call the service to forward the request
        try {
            requestBody = wrappedRequest.getMethod().equalsIgnoreCase("GET") ? null : readRequestBody(wrappedRequest);
            String backendResponse = apiGatewayService.processAndForwardRequest(wrappedRequest, requestBody);
            httpResponse.getWriter().write(backendResponse);
        } catch (Exception e) {
            httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            httpResponse.getWriter().write("Error processing request: " + e.getMessage());
        }
    }

    @Override
    public void destroy() {}

    private String readRequestBody(HttpServletRequest request) throws IOException {
        StringBuilder requestBody = new StringBuilder();
        try (BufferedReader reader = request.getReader()) {
            String line;
            while ((line = reader.readLine()) != null) {
                requestBody.append(line);
            }
        }
        return requestBody.toString();
    }
}
