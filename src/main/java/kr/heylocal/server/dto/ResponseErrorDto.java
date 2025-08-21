package kr.heylocal.server.dto;

import lombok.Data;

import java.util.Map;

@Data
public class ResponseErrorDto {
    private int errorType;
    private String errorCode;
    private String reason;
    private Map<String,String> data;
    private String title;
}
