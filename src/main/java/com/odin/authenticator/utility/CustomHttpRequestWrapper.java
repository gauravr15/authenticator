package com.odin.authenticator.utility;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.springframework.util.MultiValueMap;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;

import java.io.*;

public class CustomHttpRequestWrapper extends HttpServletRequestWrapper {

    private byte[] requestBodyBytes;

   
    public CustomHttpRequestWrapper(HttpServletRequest request, String decryptedRequestBody) throws IOException {
        super(request);
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
    
    public void setMultipartData(MultiValueMap<String, HttpEntity<?>> multipartData) {
        // Serialize multipart data to bytes and update the request body
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        FormHttpMessageConverter converter = new FormHttpMessageConverter();
        try {
            converter.write(multipartData, MediaType.MULTIPART_FORM_DATA, new HttpOutputMessage() {
                @Override
                public OutputStream getBody() throws IOException {
                    return outputStream;
                }

                @Override
                public HttpHeaders getHeaders() {
                    return new HttpHeaders();
                }
            });
            this.requestBodyBytes = outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Error serializing multipart data", e);
        }
    }


}
