package com.Calebe.logrecon.service;

import com.Calebe.logrecon.dto.LogSourceRequest;
import org.springframework.stereotype.Service;
import com.Calebe.logrecon.entity.LogSource;
import com.Calebe.logrecon.repository.LogSourceRepository;

@Service
public class LogSourceService{
    
    private final LogSourceRepository sourceRepository;

    public LogSourceService(LogSourceRepository sourceRepository){
        this.sourceRepository = sourceRepository;
    }

    public LogSource register(LogSourceRequest request){
        LogSource source = new LogSource(request.name(), request.host(), request.logType(), request.format());

        return sourceRepository.save(source);
    }
}