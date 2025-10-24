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

        StringBuilder sb = new StringBuilder();

        sb.append("\n===================\n");
        sb.append("method : ").append(requestWrapper.getMethod()).append("\n");
        sb.append("requestUri : ").append(requestWrapper.getRequestURI()).append("\n");
        sb.append("content-Type : ").append(requestWrapper.getHeader("Content-Type")).append("\n");
        sb.append("Authorization : ").append(requestWrapper.getHeader("Authorization")).append("\n");
        requestWrapper.getParameterMap().forEach((key, value) ->
                sb.append("param - key : ").append(key).append(", value : ").append(value).append("\n")
        );
        sb.append("requestBody : ").append(getRequestBody(requestWrapper.getContentAsByteArray())).append("\n");
        sb.append("status : ").append(responseWrapper.getStatus()).append("\n");
        sb.append("responseBody : ").append(getRequestBody(responseWrapper.getContentAsByteArray())).append("\n");
        sb.append("===================");

        log.info("{}", sb);

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
