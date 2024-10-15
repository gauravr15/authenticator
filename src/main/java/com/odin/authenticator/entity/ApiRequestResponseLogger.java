package com.odin.authenticator.entity;
import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "api_request_response_logger")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ApiRequestResponseLogger {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_timestamp", updatable = true)
    private Timestamp requestTimestamp;
    
    @Column(name = "response_timestamp", updatable = true)
    private Timestamp responseTimestamp;

    @Column(name = "device_id", length = 255)
    private String deviceId;

    @Column(name = "api_url", length = 255)
    private String apiUrl;
    
    @Column(name = "correlation_id", length = 255)
    private String correlationId;

    @Column(name = "request_method", length = 50)
    private String requestMethod;

    @Column(name = "request_body", length = 255)
    private String requestBody;

    @Column(name = "response_body", length = 255)
    private String responseBody;

}
