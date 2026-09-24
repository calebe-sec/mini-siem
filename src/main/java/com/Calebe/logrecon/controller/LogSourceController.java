package com.Calebe.logrecon.controller;

import com.Calebe.logrecon.dto.LogSourceRequest;
import com.Calebe.logrecon.service.LogSourceService;
import com.Calebe.logrecon.repository.LogSourceRepository;
import com.Calebe.logrecon.entity.LogSource;
import jakarta.validation.Valid;
import com.Calebe.logrecon.entity.LogEvent;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sources")
public class LogSourceController{
    
    private final LogSourceRepository repository;

    public LogSourceController(LogSourceRepository repository) {
        this.repository = repository;
    }

    @PostMapping
    public ResponseEntity<LogSource> create(@RequestBody LogSourceRequest request){
        LogSource source = new LogSource(request.name(), request.host(), request.logType(), request.format());
        return ResponseEntity.status(HttpStatus.CREATED).body(repository.save(source));
    }
}