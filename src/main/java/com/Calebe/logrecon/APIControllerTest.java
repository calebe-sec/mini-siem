package com.Calebe.logrecon;

import org.springframework.web.bind.annotation.*;
import com.Calebe.logrecon.dto.LogEventRequest;
import com.Calebe.logrecon.service.LogEventService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@RestController
public class APIControllerTest{
    
    @GetMapping("/localhost")
    public String localhost() {
        return "YOU'RE IN YOUR APICONTROLLER";
    }
}