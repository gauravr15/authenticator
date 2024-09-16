package com.odin.authenticator.utility;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class CustomHttpRequestWrapper extends HttpServletRequestWrapper {

    private final byte[] requestBodyBytes;

    // Constructor to accept HttpServletRequest and decrypted request body
    public CustomHttpRequestWrapper(HttpServletRequest request, String decryptedRequestBody) throws IOException {
        super(request);
        // Cache the decrypted request body
        this.requestBodyBytes = decryptedRequestBody.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public ServletInputStream getInputStream() {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(requestBodyBytes);
        return new ServletInputStream() {
            @Override
            public int read() throws IOException {
                return byteArrayInputStream.read();
            }

            @Override
            public boolean isFinished() {
                return byteArrayInputStream.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // Not required for this example
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    public String getRequestBody() {
        return new String(requestBodyBytes, StandardCharsets.UTF_8);
    }

}
