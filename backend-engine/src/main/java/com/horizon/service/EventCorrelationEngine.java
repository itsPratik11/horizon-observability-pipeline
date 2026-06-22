package com.horizon.service;

import com.horizon.model.CorrelatedEvent;
import com.horizon.model.ThreatAlert;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

@Service
public class EventCorrelationEngine {

    // Sliding window of alerts per IP address
    private final Map<String, List<ThreatAlert>> alertWindow = new ConcurrentHashMap<>();
    private static final Duration WINDOW_SIZE = Duration.ofMinutes(1);

    public Optional<CorrelatedEvent> correlate(ThreatAlert alert) {
        if (alert == null || alert.getSourceIp() == null) {
            return Optional.empty();
        }

        String ip = alert.getSourceIp();
        Instant now = Instant.now();

        // Retrieve or initialize list for this IP
        List<ThreatAlert> alerts = alertWindow.computeIfAbsent(ip, k -> new CopyOnWriteArrayList<>());
        alerts.add(alert);

        // Prune expired alerts outside the sliding window
        pruneExpiredAlerts(alerts, now);

        // Evaluate correlation rules
        return evaluateRules(ip, alerts, now);
    }

    private void pruneExpiredAlerts(List<ThreatAlert> alerts, Instant now) {
        alerts.removeIf(alert -> Duration.between(alert.getTimestamp(), now).compareTo(WINDOW_SIZE) > 0);
    }

    private Optional<CorrelatedEvent> evaluateRules(String ip, List<ThreatAlert> alerts, Instant now) {
        if (alerts.size() < 2) {
            return Optional.empty();
        }

        // Count threats by type
        long bruteForceCount = alerts.stream().filter(a -> "BRUTE_FORCE".equals(a.getThreatType())).count();
        long webExploitCount = alerts.stream().filter(a -> 
                "SQL_INJECTION".equals(a.getThreatType()) || 
                "XSS".equals(a.getThreatType()) || 
                "PATH_TRAVERSAL".equals(a.getThreatType())
        ).count();

        List<ThreatAlert> sortedAlerts = alerts.stream()
                .sorted(Comparator.comparing(ThreatAlert::getTimestamp))
                .collect(Collectors.toList());

        Instant firstSeen = sortedAlerts.get(0).getTimestamp();
        Instant lastSeen = sortedAlerts.get(sortedAlerts.size() - 1).getTimestamp();

        // Rule 1: Brute Force threshold
        if (bruteForceCount >= 5) {
            return Optional.of(CorrelatedEvent.builder()
                    .id(UUID.randomUUID().toString())
                    .title("High-Frequency Brute Force Attack Detected")
                    .description("Detected " + bruteForceCount + " authentication failures from IP " + ip + " within 1 minute.")
                    .severity("HIGH")
                    .alerts(new ArrayList<>(alerts))
                    .firstSeen(firstSeen)
                    .lastSeen(lastSeen)
                    .status("ACTIVE")
                    .build());
        }

        // Rule 2: Web exploitation attempts
        if (webExploitCount >= 3) {
            return Optional.of(CorrelatedEvent.builder()
                    .id(UUID.randomUUID().toString())
                    .title("Active Web Application Exploitation / Vulnerability Scan")
                    .description("Detected " + webExploitCount + " high-severity web payloads (SQLi/XSS/Traversal) from IP " + ip + " within 1 minute.")
                    .severity("CRITICAL")
                    .alerts(new ArrayList<>(alerts))
                    .firstSeen(firstSeen)
                    .lastSeen(lastSeen)
                    .status("ACTIVE")
                    .build());
        }

        // Rule 3: Multi-vector / general correlation
        if (alerts.size() >= 4) {
            return Optional.of(CorrelatedEvent.builder()
                    .id(UUID.randomUUID().toString())
                    .title("Multi-Vector Security Incidents Correlated")
                    .description("Detected " + alerts.size() + " correlated security alerts from IP " + ip + " within 1 minute.")
                    .severity("MEDIUM")
                    .alerts(new ArrayList<>(alerts))
                    .firstSeen(firstSeen)
                    .lastSeen(lastSeen)
                    .status("ACTIVE")
                    .build());
        }

        return Optional.empty();
    }
}
