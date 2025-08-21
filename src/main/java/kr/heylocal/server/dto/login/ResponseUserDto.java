package kr.heylocal.server.dto.login;

import lombok.Data;

import java.util.LinkedList;

@Data
public class ResponseUserDto {
    private String userKey;
    private String scope;
    private LinkedList<String> agreeTerms;
    private String name;
    private String callingCode;
    private String phone;
    private String birthday;
    private String ci;
    private String di;
    private String gender;
    private String nationality;
    private String email;
}
