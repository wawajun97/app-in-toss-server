package kr.heylocal.server.dto;

import lombok.Data;

@Data
public class ResponseDto<T> {
    private String resultType;
    private ResponseErrorDto error;
    private T success;
}
