package com.Calebe.logrecon.controller;

import com.Calebe.logrecon.dto.AlertRequest;
import com.Calebe.logrecon.entity.Alert;
import com.Calebe.logrecon.repository.AlertRepository;
import com.Calebe.logrecon.service.AlertService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService service;
    private final AlertRepository repository;

    public AlertController(AlertService service, AlertRepository repository) {
        this.service = service;
        this.repository = repository;
    }

    @PostMapping
    public ResponseEntity<Alert> receive(@Valid @RequestBody AlertRequest request) {
        Alert salvo = service.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(salvo);
    }

    @GetMapping
    public List<Alert> list() {
        return repository.findAll();
    }
}