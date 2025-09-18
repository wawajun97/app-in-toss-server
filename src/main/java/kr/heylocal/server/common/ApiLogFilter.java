package kr.heylocal.server.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;


@Component
@Slf4j
public class ApiLogFilter implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper((HttpServletRequest) servletRequest);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper((HttpServletResponse) servletResponse);

        filterChain.doFilter(requestWrapper, responseWrapper);

        log.info("===================");
        log.info("method : {}", requestWrapper.getMethod());
        log.info("requestUri : {}", requestWrapper.getRequestURI());
        log.info("content-Type : {}", requestWrapper.getHeader("Content-Type"));
        log.info("Authorization : {}", requestWrapper.getHeader("Authorization"));
        requestWrapper.getParameterMap().forEach((key, value) ->
                log.info("param - key : {} , value : {}", key, value)
        );
        log.info("requestBody : {}", getRequestBody(requestWrapper.getContentAsByteArray()));
        log.info("status : {}", responseWrapper.getStatus());
        log.info("responseBody : {}", getRequestBody(responseWrapper.getContentAsByteArray()));
        log.info("===================");

        // Response body를 클라이언트로 다시 전달
        responseWrapper.copyBodyToResponse();
    }

    private String getRequestBody(byte[] content) {
        if (content.length == 0) {
            return "";
        }

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            Object json = objectMapper.readTree(content);
            return objectMapper.writeValueAsString(json); // 한 줄 JSON 문자열 반환
        } catch (IOException e) {
            return new String(content, StandardCharsets.UTF_8);
        }
    }
}
