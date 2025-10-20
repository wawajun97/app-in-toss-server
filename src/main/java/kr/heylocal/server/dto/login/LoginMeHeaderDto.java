package kr.heylocal.server.dto.login;

import kr.heylocal.server.dto.HeaderDto;
import org.springframework.http.HttpHeaders;

import java.util.function.Consumer;

public class LoginMeHeaderDto implements HeaderDto {
    private String Authorization;
    @Override
    public Consumer<HttpHeaders> toHeader() {
        return httpHeaders -> {
            httpHeaders.add("Authorization", this.Authorization);
        };
    }
}
