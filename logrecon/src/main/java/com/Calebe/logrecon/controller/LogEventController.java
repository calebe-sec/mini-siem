package com.Calebe.logrecon.controller;

import com.Calebe.logrecon.dto.LogEventRequest;
import com.Calebe.logrecon.entity.LogEvent;
import com.Calebe.logrecon.repository.LogEventRepository;
import com.Calebe.logrecon.service.LogEventService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/events")
public class LogEventController {

    private final LogEventService service;
    private final LogEventRepository repository;

    public LogEventController(LogEventService service, LogEventRepository repository) {
        this.service = service;
        this.repository = repository;
    }

    @PostMapping
    public ResponseEntity<LogEvent> recieve(@Valid @RequestBody LogEventRequest request) {
        LogEvent salvo = service.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(salvo);
    }

    @GetMapping
    public List<LogEvent> list() {
        return repository.findAll();
    }
}