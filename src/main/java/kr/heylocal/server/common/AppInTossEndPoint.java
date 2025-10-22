package kr.heylocal.server.common;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public enum AppInTossEndPoint {
    REFRESH_TOKEN("/user/oauth2/refresh-token"),
    GENERATE_TOKEN("/user/oauth2/generate-token"),
    REMOVE_BY_USER_KEY("/user/oauth2/access/remove-by-user-key"),
    REMOVE_BY_ACCESS_TOKEN("/user/oauth2/access/remove-by-access-token"),
    LOGIN_ME("/user/oauth2/login-me");


    private String path;
    public String getPath() { return path; }
}