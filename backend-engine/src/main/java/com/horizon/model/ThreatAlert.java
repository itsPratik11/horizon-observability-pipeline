package com.horizon.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatAlert {
    private String id;
    private String logEntryId;
    private String threatType; // e.g. SQL_INJECTION, BRUTE_FORCE, XSS, SUSPICIOUS_IP
    private String severity;   // e.g. LOW, MEDIUM, HIGH, CRITICAL
    private double confidence; // e.g. 0.0 to 1.0
    private Instant timestamp;
    private String description;
    private String sourceIp;
}
