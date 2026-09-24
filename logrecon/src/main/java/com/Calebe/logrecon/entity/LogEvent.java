package com.Calebe.logrecon.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AccessLevel;
import java.time.LocalDateTime;

//getter is a easier way
@Getter
@NoArgsConstructor(access=AccessLevel.PROTECTED)
//Log Event Table create;
@Entity
@Table(name="log_event")
public class LogEvent{
    
    //create the id to this class
    @Id
    @GeneratedValue(strategy=GenerationType.AUTO)
    private Long id;

    //get ID to Log Source;
    @ManyToOne
    @JoinColumn(name="source_id")
    private LogSource source;

    @Lob
    @Column(name="raw_message", nullable=false)
    private String rawMessage;
    
    //time come from the parser
    private LocalDateTime timestamp;
    
    private String sourceIp;
    private String eventType;
    private String username;
    private String severity;

    //protect constructor for database;
    //but lombok makes it easier
    //protected LogEvent(){}

    public LogEvent(LogSource source, LocalDateTime timestamp, String sourceIp, String eventType, String username, String rawMessage, String severity){
        this.source = source;
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
        this.eventType = eventType;
        this.username = username;
        this.rawMessage = rawMessage;
        this.severity = severity;
    }

    //change all data to String;
    @Override
    public String toString(){
        return String.format("LogEvent[id=%d, sourceId=%d, timestamp=%tF %tT, sourceIp=%s, username=%s, eventType=%s]",
            id, source.getId(), timestamp, timestamp, sourceIp, username, eventType
         );
    }
}