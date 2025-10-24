package kr.heylocal.server.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ResponseErrorDto {
    private int errorType;
    private String errorCode;
    private String reason;
    private Map<String,String> data;
    private String title;
}
