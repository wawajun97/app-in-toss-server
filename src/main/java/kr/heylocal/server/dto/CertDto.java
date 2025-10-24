package kr.heylocal.server.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertDto {
    private String resultType;
    private String triggerType;
    private String sessionKey;
    private String userName;
    private String userPhone;
    private String userBirthday;
}
