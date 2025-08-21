package kr.heylocal.server.dto.login;

import lombok.Data;

@Data
public class GenerateTokenBodyDto {
    private String authorizationCode;
    private String referrer;
}
