package com.Calebe.logrecon.dto;

import java.time.LocalDateTime;

public record LogEventRequest(String sourceName, LocalDateTime timestamp,String sourceIp,
                              String eventType, String username, String rawMessage, String severity) {}