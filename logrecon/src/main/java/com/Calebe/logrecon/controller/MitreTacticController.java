package com.Calebe.logrecon.controller;

import com.Calebe.logrecon.dto.MitreTacticRequest;
import com.Calebe.logrecon.entity.MitreTactic;
import com.Calebe.logrecon.service.MitreTacticService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/tactics")
public class MitreTacticController {

    private final MitreTacticService service;

    public MitreTacticController(MitreTacticService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<MitreTactic> receive(@Valid @RequestBody MitreTacticRequest request) {
        MitreTactic salvo = service.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(salvo);
    }
}