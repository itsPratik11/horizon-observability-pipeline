package com.horizon.service;

import com.horizon.model.LogEntry;
import java.util.Optional;

public interface LogParsingService {
    Optional<LogEntry> parse(String rawLog);
}
