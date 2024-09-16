package com.odin.authenticator.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.odin.authenticator.utility.CustomHttpRequestWrapper;
import com.odin.authenticator.utility.EncryptionDecryption;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class CustomFilter implements Filter {

    private final EncryptionDecryption encryptionService;
    private final ObjectMapper objectMapper;

    public CustomFilter(EncryptionDecryption encryptionService, ObjectMapper objectMapper) {
        this.encryptionService = encryptionService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String requestTimestamp = httpRequest.getHeader("requestTimestamp");
        if (requestTimestamp == null) {
            httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            httpResponse.getWriter().write("Missing requestTimestamp header");
            return;
        }

        if ("GET".equalsIgnoreCase(httpRequest.getMethod()) || httpRequest.getContentLength() == 0) {
            chain.doFilter(request, response);
            return;
        }

        // Wrap the request only if not wrapped already
        CustomHttpRequestWrapper wrappedRequest;
        if (!(httpRequest instanceof CustomHttpRequestWrapper)) {
            // Read the original request body in Java 8 using BufferedReader
            String requestBody = readRequestBody(httpRequest);
            System.out.println("Request Body: " + requestBody);  // Log request body

            Map<String, Object> requestMap = objectMapper.readValue(requestBody, Map.class);
            System.out.println("Request Map: " + requestMap);  // Log parsed map

            String encryptedRequest = (String) requestMap.get("request");
            if (encryptedRequest == null) {
                httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                httpResponse.getWriter().write("Missing 'request' field in JSON");
                return;
            }

            // Decrypt the request data
            String decryptedJson = null;
			try {
				decryptedJson = encryptionService.decrypt(encryptedRequest, requestTimestamp);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            System.out.println("Decrypted JSON: " + decryptedJson);  // Log decrypted JSON

            Map<String, Object> decryptedMap = objectMapper.readValue(decryptedJson, Map.class);
            System.out.println("Decrypted Map: " + decryptedMap);  // Log decrypted map

            // Wrap decrypted request body
            wrappedRequest = new CustomHttpRequestWrapper(httpRequest, decryptedJson);

            // Log the decrypted request body
            System.out.println("Request Body in Filter Before Forwarding: " + decryptedJson);
        } else {
            wrappedRequest = (CustomHttpRequestWrapper) httpRequest;
        }

        // Forward the wrapped request in the filter chain
        chain.doFilter(wrappedRequest, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void destroy() {}

    // Helper method to read the request body in Java 8
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
