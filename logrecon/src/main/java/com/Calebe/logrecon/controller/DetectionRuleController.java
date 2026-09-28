package com.Calebe.logrecon.controller;

import com.Calebe.logrecon.dto.DetectionRuleRequest;
import com.Calebe.logrecon.entity.DetectionRule;
import com.Calebe.logrecon.service.DetectionRuleService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/rules")
public class DetectionRuleController {

    private final DetectionRuleService service;

    public DetectionRuleController(DetectionRuleService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<DetectionRule> receive(@Valid @RequestBody DetectionRuleRequest request) {
        DetectionRule salvo = service.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(salvo);
    }
}