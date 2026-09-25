package com.Calebe.logrecon.controller;

import com.Calebe.logrecon.dto.AlertRequest;
import com.Calebe.logrecon.entity.Alert;
import com.Calebe.logrecon.service.AlertService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService service;

    public AlertController(AlertService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<Alert> receber(@Valid @RequestBody AlertRequest request) {
        Alert salvo = service.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(salvo);
    }
}