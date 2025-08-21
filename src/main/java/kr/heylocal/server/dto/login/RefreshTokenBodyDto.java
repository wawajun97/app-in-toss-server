package kr.heylocal.server.dto.login;

import lombok.Data;

@Data
public class RefreshTokenBodyDto {
    private String refreshToken;
}
