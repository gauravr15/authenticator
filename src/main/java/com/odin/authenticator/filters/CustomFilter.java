package com.odin.authenticator.filters;

import java.io.BufferedReader;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

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

        // CORS Handling
        String origin = httpRequest.getHeader("Origin");
        if (origin != null && isValidOrigin(origin)) {
            httpResponse.setHeader("Access-Control-Allow-Origin", origin);
            httpResponse.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            httpResponse.setHeader("Access-Control-Allow-Headers", "Content-Type, appLang, requestTimestamp, correlationId");
            httpResponse.setHeader("Access-Control-Expose-Headers", "X-Correlation-ID, responseTimestamp"); 
            httpResponse.setHeader("Access-Control-Allow-Credentials", "true");
            httpResponse.setHeader("Access-Control-Max-Age", "3600");
        }

        // Handle preflight (OPTIONS) requests
        if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
            httpResponse.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        // Generate or extract Correlation ID
        String correlationId = httpRequest.getHeader(ApplicationConstants.CORRELATION_ID_HEADER_NAME);
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = UUID.randomUUID().toString();
        }

        // Add correlation ID to MDC for logging
        MDC.put(ApplicationConstants.CORRELATION_ID_HEADER_NAME, correlationId);

        // Add correlation ID to the response header
        httpResponse.setHeader(ApplicationConstants.CORRELATION_ID_HEADER_NAME, correlationId);
        String appLang = httpRequest.getHeader(ApplicationConstants.APP_LANG);
        if(ObjectUtils.isEmpty(appLang)) {
            httpResponse.setHeader(ApplicationConstants.APP_LANG, ApplicationConstants.DEFAULT_LANGUAGE);
        } else {
            httpResponse.setHeader(ApplicationConstants.APP_LANG, appLang);
        }

        String requestTimestamp = httpRequest.getHeader("requestTimestamp");
        String requestURI = httpRequest.getRequestURI();
        String requestBody = null;

        // If encryption is disabled or the API is bypassed, proceed with URL transformation and REST call
        if (!isEncryptionEnabled || bypassApis.contains(requestURI.replace(ApplicationConstants.CONTEXT_PATH, ""))) {
            try {
                requestBody = httpRequest.getMethod().equalsIgnoreCase("GET") ? null : readRequestBody(httpRequest);
                String backendResponse = apiGatewayService.processAndForwardRequest(httpRequest, requestBody);

                // Encrypt and send the response
				if (isEncryptionEnabled) {
					sendEncryptedResponse(httpResponse, backendResponse);
				}
				else {
					 httpResponse.setContentType("application/json;charset=UTF-8");
				        httpResponse.setCharacterEncoding("UTF-8");
				        httpResponse.setHeader("responseTimestamp", requestTimestamp);
				       
				        // Write the encrypted response
				        httpResponse.getWriter().write(backendResponse);
				}
            } catch (Exception e) {
                httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                httpResponse.getWriter().write("Error processing request: " + e.getMessage());
            } finally {
                // Clear MDC after processing
                MDC.clear();
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
        if (isEncryptionEnabled) {
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

            // Encrypt and send the response
			if (isEncryptionEnabled) {
				sendEncryptedResponse(httpResponse, backendResponse);
			}
			else {
				 httpResponse.setContentType("application/json;charset=UTF-8");
			        httpResponse.setCharacterEncoding("UTF-8");
			        httpResponse.setHeader("responseTimestamp", requestTimestamp);
			       
			        // Write the encrypted response
			        httpResponse.getWriter().write(backendResponse);
			}

        } catch (Exception e) {
            httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            httpResponse.getWriter().write("Error processing request: " + e.getMessage());
        } finally {
            // Clear MDC after processing
            MDC.clear();
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

    // Encrypt the response and set the current timestamp in the response header
    private void sendEncryptedResponse(HttpServletResponse httpResponse, String backendResponse) throws Exception {
    	
    	long currentEpochMillis = Instant.now().toEpochMilli();
    	  // For milliseconds
        // Encrypt the response
        String encryptedResponse = encryptionService.encrypt(backendResponse, String.valueOf(currentEpochMillis));

        // Create the response structure
        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("response", encryptedResponse);
        String jsonResponse = objectMapper.writeValueAsString(responseMap);

        // Set response content type and character encoding
        httpResponse.setContentType("application/json;charset=UTF-8");
        httpResponse.setCharacterEncoding("UTF-8");
        httpResponse.setHeader("responseTimestamp", String.valueOf(currentEpochMillis));
       
        // Write the encrypted response
        httpResponse.getWriter().write(jsonResponse);
    }

    // Validate origin. You can add custom logic to restrict specific origins if needed.
    private boolean isValidOrigin(String origin) {
        // Example: allow all origins for simplicity. Customize as needed.
        return true;
    }
}
