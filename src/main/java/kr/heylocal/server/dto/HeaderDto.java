package kr.heylocal.server.dto;


import org.springframework.http.HttpHeaders;

import java.util.function.Consumer;

public interface HeaderDto {
    public Consumer<HttpHeaders> toHeader();
}
