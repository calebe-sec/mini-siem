package com.Calebe.logrecon.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AccessLevel;

//getter is a easier way
@Getter
@NoArgsConstructor(access=AccessLevel.PROTECTED)
@Entity
@Table(name="log_source")
public class LogSource{
    
    //create the id to this class
    @Id
    @GeneratedValue
    private Long id;

    private String name;
    private String host;
    private String logType;
    private String format;

    //protect constructor for database;
    //but lombok makes it easier
    // protected LogSource(){}

    public LogSource(String name, String host, String logType, String format){
        this.name = name;
        this.host = host;
        this.logType = logType;
        this.format = format;

    }
    
    @Override
    public String toString(){
        return String.format("LogSource[id=%d, name=%s, host=%s, logType=%s, format=%s]",
            id, name, host, logType, format
        );
    }

}