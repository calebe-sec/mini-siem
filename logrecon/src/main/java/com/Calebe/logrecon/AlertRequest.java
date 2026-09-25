package com.Calebe.logrecon.dto;

import java.util.List;

public record AlertRequest(String rule, String status, String description, List<Long> logEventIds){

}