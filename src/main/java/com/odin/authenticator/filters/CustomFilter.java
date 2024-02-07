package com.odin.authenticator.filters;

import com.odin.authenticator.utility.EncryptionDecryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Order(1)
public class CustomFilter implements Filter {

    @Value("${api-key}")
    private String apiKey;

    @Value("${api-secret}")
    private String apiSecret;

    private String iv;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization logic here
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String apiName = httpRequest.getRequestURI();

        if (apiName.contains("/login")) {
            String incomingApiKey = httpRequest.getHeader("x-api-key");
            String incomingApiSecret = httpRequest.getHeader("x-api-secret");

            if (apiKey != null && apiSecret != null &&
                apiKey.equals(incomingApiKey) && apiSecret.equals(incomingApiSecret)) {
                // Proceed with the filter chain
                chain.doFilter(request, response);
            } else {
                // Unauthorized access
                httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } else {
            if (!httpRequest.getMethod().equals("GET")) {
                try {
                    String encryptedRequestBody = getRequestBody(httpRequest);
                    EncryptionDecryption encryptionDecryption = new EncryptionDecryption(iv);
                    String decryptedRequestBody = encryptionDecryption.decrypt(encryptedRequestBody);
                    // Modify the request with decrypted body
                    HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(httpRequest) {
                        @Override
                        public BufferedReader getReader() throws IOException {
                            return new BufferedReader(new InputStreamReader(getInputStream()));
                        }

                        @Override
                        public ServletInputStream getInputStream() throws IOException {
                            final byte[] decryptedBytes = decryptedRequestBody.getBytes();
                            return new ServletInputStream() {
                                @Override
                                public int read() throws IOException {
                                    return decryptedBytes.length == 0 ? -1 : decryptedBytes[0];
                                }

                                @Override
                                public boolean isFinished() {
                                    return decryptedBytes.length == 0;
                                }

                                @Override
                                public boolean isReady() {
                                    return decryptedBytes.length > 0;
                                }

                                @Override
                                public void setReadListener(ReadListener listener) {
                                    // Do nothing
                                }
                            };
                        }
                    };
                    chain.doFilter(requestWrapper, response);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
                    // Handle decryption errors
                    httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    e.printStackTrace();
                }
            } else {
                // Continue the filter chain for GET requests
                chain.doFilter(request, response);
            }
        }
    }

    @Override
    public void destroy() {
        // Cleanup logic here
    }

    private String getRequestBody(HttpServletRequest request) throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;
        BufferedReader reader = request.getReader();
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }
}
