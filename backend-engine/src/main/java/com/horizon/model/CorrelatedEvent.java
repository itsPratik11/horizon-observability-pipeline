package com.horizon.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CorrelatedEvent {
    private String id;
    private String title;
    private String description;
    private String severity;
    private List<ThreatAlert> alerts;
    private Instant firstSeen;
    private Instant lastSeen;
    private String status;
}
