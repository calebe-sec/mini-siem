package com.Calebe.logrecon.service;

import com.Calebe.logrecon.dto.LogEventRequest;
import org.springframework.stereotype.Service;
import com.Calebe.logrecon.entity.LogEvent;
import com.Calebe.logrecon.entity.LogSource;
import com.Calebe.logrecon.repository.LogEventRepository;
import com.Calebe.logrecon.repository.LogSourceRepository;

@Service
public class LogEventService {

    private final LogEventRepository eventRepository;
    private final LogSourceRepository sourceRepository;

    public LogEventService(LogEventRepository eventRepository, LogSourceRepository sourceRepository) {
        this.eventRepository = eventRepository;
        this.sourceRepository = sourceRepository;
    }

    public LogEvent register(LogEventRequest request) {
        LogSource source = sourceRepository.findByName(request.sourceName())
            .orElseThrow(() -> new IllegalArgumentException("Unknown source: " + request.sourceName()));

        LogEvent event = new LogEvent(
            source, request.timestamp(), request.sourceIp(),
            request.eventType(), request.username(), request.rawMessage(), request.severity()
        );

        return eventRepository.save(event);
    }
}