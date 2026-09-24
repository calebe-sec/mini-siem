package com.Calebe.logrecon.controller;

import com.Calebe.logrecon.dto.LogEventRequest;
import com.Calebe.logrecon.service.LogEventService;
import jakarta.validation.Valid;
import com.Calebe.logrecon.entity.LogEvent;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/events")
public class LogEventController{
    private final LogEventService service;

    public LogEventController(LogEventService service){
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<LogEvent>receive(@Valid @RequestBody LogEventRequest request){
        LogEvent saved = service.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }
}