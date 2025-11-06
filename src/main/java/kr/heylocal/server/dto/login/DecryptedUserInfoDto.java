package kr.heylocal.server.dto.login;

import lombok.AllArgsConstructor;
import lombok.Getter;
@Getter
@AllArgsConstructor
public class DecryptedUserInfoDto {
    private String phone;
    private String email;
    private String callingCode;
}