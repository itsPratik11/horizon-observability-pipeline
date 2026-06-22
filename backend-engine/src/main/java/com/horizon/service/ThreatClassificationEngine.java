package com.horizon.service;

import com.horizon.model.LogEntry;
import com.horizon.model.ThreatAlert;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
public class ThreatClassificationEngine {

    // Regex patterns for common attacks
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "(?i)(SELECT|UNION|SELECT.*FROM|INSERT INTO|UPDATE.*SET|DELETE FROM|DROP TABLE|OR\\s+\\d+=\\d+|--|#)"
    );

    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)(<script.*?>|javascript:|onload\\s*=|onerror\\s*=|<iframe.*?>)"
    );

    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
            "(?i)(\\.\\./|\\.\\.\\\\|/etc/passwd|/windows/win\\.ini|/boot\\.ini)"
    );

    private static final Pattern BRUTE_FORCE_PATTERN = Pattern.compile(
            "(?i)(failed password|invalid credentials|authentication failed|login failed|unauthorized attempt)"
    );

    public Optional<ThreatAlert> classify(LogEntry logEntry) {
        if (logEntry == null || logEntry.getMessage() == null) {
            return Optional.empty();
        }

        String msg = logEntry.getMessage();

        // 1. Check Path Traversal (High Severity)
        if (PATH_TRAVERSAL_PATTERN.matcher(msg).find()) {
            return Optional.of(ThreatAlert.builder()
                    .id(UUID.randomUUID().toString())
                    .logEntryId(logEntry.getId())
                    .threatType("PATH_TRAVERSAL")
                    .severity("HIGH")
                    .confidence(0.95)
                    .timestamp(Instant.now())
                    .description("Detected directory traversal attempt in log message: " + msg)
                    .sourceIp(logEntry.getIpAddress())
                    .build());
        }

        // 2. Check SQL Injection (Critical Severity)
        if (SQL_INJECTION_PATTERN.matcher(msg).find()) {
            return Optional.of(ThreatAlert.builder()
                    .id(UUID.randomUUID().toString())
                    .logEntryId(logEntry.getId())
                    .threatType("SQL_INJECTION")
                    .severity("CRITICAL")
                    .confidence(0.90)
                    .timestamp(Instant.now())
                    .description("Detected SQL Injection signature in log message: " + msg)
                    .sourceIp(logEntry.getIpAddress())
                    .build());
        }

        // 3. Check XSS (High Severity)
        if (XSS_PATTERN.matcher(msg).find()) {
            return Optional.of(ThreatAlert.builder()
                    .id(UUID.randomUUID().toString())
                    .logEntryId(logEntry.getId())
                    .threatType("XSS")
                    .severity("HIGH")
                    .confidence(0.85)
                    .timestamp(Instant.now())
                    .description("Detected Cross-Site Scripting signature in log message: " + msg)
                    .sourceIp(logEntry.getIpAddress())
                    .build());
        }

        // 4. Check Brute Force indicators (Medium Severity)
        if (BRUTE_FORCE_PATTERN.matcher(msg).find()) {
            return Optional.of(ThreatAlert.builder()
                    .id(UUID.randomUUID().toString())
                    .logEntryId(logEntry.getId())
                    .threatType("BRUTE_FORCE")
                    .severity("MEDIUM")
                    .confidence(0.80)
                    .timestamp(Instant.now())
                    .description("Detected login/authentication failure indicator: " + msg)
                    .sourceIp(logEntry.getIpAddress())
                    .build());
        }

        // 5. Check Suspicious Status code in metadata (if CLF)
        if (logEntry.getMetadata() != null && "CLF".equals(logEntry.getMetadata().get("logFormat"))) {
            String statusCode = logEntry.getMetadata().get("statusCode");
            if ("401".equals(statusCode) || "403".equals(statusCode)) {
                return Optional.of(ThreatAlert.builder()
                        .id(UUID.randomUUID().toString())
                        .logEntryId(logEntry.getId())
                        .threatType("UNAUTHORIZED_ACCESS")
                        .severity("MEDIUM")
                        .confidence(0.70)
                        .timestamp(Instant.now())
                        .description("Unauthorized access attempt (HTTP " + statusCode + ")")
                        .sourceIp(logEntry.getIpAddress())
                        .build());
            }
        }

        return Optional.empty();
    }
}
