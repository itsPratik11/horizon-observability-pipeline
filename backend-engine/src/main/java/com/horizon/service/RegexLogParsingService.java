package com.horizon.service;

import com.horizon.model.LogEntry;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class RegexLogParsingService implements LogParsingService {

    // Common Log Format (CLF)
    // Example: 127.0.0.1 - - [22/Jun/2026:11:40:13 +0530] "GET /api/v1/logs HTTP/1.1" 200 2326
    private static final Pattern CLF_PATTERN = Pattern.compile(
            "^(\\S+) \\S+ \\S+ \\[(.*?)\\] \"(.*?)\" (\\d{3}) (\\d+|-)$"
    );

    // Syslog Format (RFC 3164)
    // Example: <34>Oct 11 22:14:15 myhost security-service: Failed password for root from 192.168.1.5 port 22 ssh2
    private static final Pattern SYSLOG_PATTERN = Pattern.compile(
            "^<(\\d+)>([A-Za-z]{3}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}) (\\S+) (.*?): (.*)$"
    );

    // Standard Application Log Format
    // Example: 2026-06-22 11:40:13.123 [main] INFO  com.horizon.Service - Ingestion started successfully from client 192.168.1.10
    private static final Pattern APP_LOG_PATTERN = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\S*) \\[([^\\]]+)\\] ([A-Z]+)\\s+(\\S+) - (.*)$"
    );

    // Generic fallback IP extractor
    private static final Pattern IP_EXTRACTOR = Pattern.compile(
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    );

    @Override
    public Optional<LogEntry> parse(String rawLog) {
        if (rawLog == null || rawLog.isBlank()) {
            return Optional.empty();
        }

        rawLog = rawLog.trim();

        // 1. Try App Log Pattern first (very common)
        Matcher appMatcher = APP_LOG_PATTERN.matcher(rawLog);
        if (appMatcher.matches()) {
            return Optional.of(parseAppLog(appMatcher, rawLog));
        }

        // 2. Try CLF Pattern
        Matcher clfMatcher = CLF_PATTERN.matcher(rawLog);
        if (clfMatcher.matches()) {
            return Optional.of(parseClfLog(clfMatcher, rawLog));
        }

        // 3. Try Syslog Pattern
        Matcher syslogMatcher = SYSLOG_PATTERN.matcher(rawLog);
        if (syslogMatcher.matches()) {
            return Optional.of(parseSyslogLog(syslogMatcher, rawLog));
        }

        // 4. Fallback Generic Parsing
        return Optional.of(parseGenericLog(rawLog));
    }

    private LogEntry parseAppLog(Matcher matcher, String rawLog) {
        String timestampStr = matcher.group(1);
        String thread = matcher.group(2);
        String level = matcher.group(3);
        String className = matcher.group(4);
        String message = matcher.group(5);

        Instant timestamp = parseInstantSafely(timestampStr);
        String ipAddress = extractIpAddress(message);

        Map<String, String> metadata = new HashMap<>();
        metadata.put("logFormat", "APPLICATION");
        metadata.put("thread", thread);
        metadata.put("class", className);

        return LogEntry.builder()
                .id(UUID.randomUUID().toString())
                .timestamp(timestamp)
                .level(level)
                .serviceName(className)
                .message(message)
                .ipAddress(ipAddress)
                .rawLog(rawLog)
                .metadata(metadata)
                .build();
    }

    private LogEntry parseClfLog(Matcher matcher, String rawLog) {
        String ipAddress = matcher.group(1);
        String timestampStr = matcher.group(2);
        String request = matcher.group(3);
        String statusCode = matcher.group(4);
        String sizeBytes = matcher.group(5);

        Instant timestamp = parseInstantSafely(timestampStr);

        Map<String, String> metadata = new HashMap<>();
        metadata.put("logFormat", "CLF");
        metadata.put("request", request);
        metadata.put("statusCode", statusCode);
        metadata.put("sizeBytes", sizeBytes);

        // Determine Level based on status code
        String level = "INFO";
        try {
            int status = Integer.parseInt(statusCode);
            if (status >= 500) {
                level = "ERROR";
            } else if (status >= 400) {
                level = "WARN";
            }
        } catch (NumberFormatException ignored) {}

        return LogEntry.builder()
                .id(UUID.randomUUID().toString())
                .timestamp(timestamp)
                .level(level)
                .serviceName("web-gateway")
                .message(request)
                .ipAddress(ipAddress)
                .rawLog(rawLog)
                .metadata(metadata)
                .build();
    }

    private LogEntry parseSyslogLog(Matcher matcher, String rawLog) {
        String priStr = matcher.group(1);
        String timestampStr = matcher.group(2);
        String host = matcher.group(3);
        String serviceName = matcher.group(4);
        String message = matcher.group(5);

        Instant timestamp = parseInstantSafely(timestampStr);
        String ipAddress = extractIpAddress(message);
        if (ipAddress == null) {
            ipAddress = extractIpAddress(host);
        }

        Map<String, String> metadata = new HashMap<>();
        metadata.put("logFormat", "SYSLOG");
        metadata.put("priority", priStr);
        metadata.put("host", host);

        // Determine level from PRI if possible
        String level = "INFO";
        try {
            int pri = Integer.parseInt(priStr);
            int severity = pri & 7; // Severity is last 3 bits
            if (severity <= 3) {
                level = "ERROR";
            } else if (severity == 4) {
                level = "WARN";
            }
        } catch (NumberFormatException ignored) {}

        return LogEntry.builder()
                .id(UUID.randomUUID().toString())
                .timestamp(timestamp)
                .level(level)
                .serviceName(serviceName)
                .message(message)
                .ipAddress(ipAddress)
                .rawLog(rawLog)
                .metadata(metadata)
                .build();
    }

    private LogEntry parseGenericLog(String rawLog) {
        String ipAddress = extractIpAddress(rawLog);
        String level = "INFO";
        String upperLog = rawLog.toUpperCase();
        if (upperLog.contains("ERROR") || upperLog.contains("SEVERE") || upperLog.contains("FAIL")) {
            level = "ERROR";
        } else if (upperLog.contains("WARN")) {
            level = "WARN";
        } else if (upperLog.contains("DEBUG")) {
            level = "DEBUG";
        }

        Map<String, String> metadata = new HashMap<>();
        metadata.put("logFormat", "GENERIC");

        return LogEntry.builder()
                .id(UUID.randomUUID().toString())
                .timestamp(Instant.now())
                .level(level)
                .serviceName("unknown-service")
                .message(rawLog)
                .ipAddress(ipAddress)
                .rawLog(rawLog)
                .metadata(metadata)
                .build();
    }

    private Instant parseInstantSafely(String value) {
        try {
            return Instant.parse(value);
        } catch (Exception e) {
            // Safe fallback
            return Instant.now();
        }
    }

    private String extractIpAddress(String text) {
        if (text == null) return null;
        Matcher matcher = IP_EXTRACTOR.matcher(text);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }
}
