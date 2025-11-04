package kr.heylocal.server.dto.login;

import lombok.Data;

@Data
public class CallbackLogoutDto {
    private Integer userKey;
    private String referrer;
}
