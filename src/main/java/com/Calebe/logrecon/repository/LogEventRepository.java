package com.Calebe.logrecon.repository;

import com.Calebe.logrecon.entity.LogEvent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LogEventRepository extends JpaRepository<LogEvent, Long>{

}