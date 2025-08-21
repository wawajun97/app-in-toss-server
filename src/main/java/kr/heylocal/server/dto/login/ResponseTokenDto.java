package kr.heylocal.server.dto.login;

import lombok.Data;

@Data
public class ResponseTokenDto {
    private String accessToken;
    private String refreshToken;
    private int expiresIn;
    private String tokenType;
    private String scope;
}
