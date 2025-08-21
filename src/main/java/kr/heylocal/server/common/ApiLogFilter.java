package kr.heylocal.server.common;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;


@Component
@Slf4j
public class ApiLogFilter implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper((HttpServletRequest) servletRequest);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper((HttpServletResponse) servletResponse);

        log.info("===================");
        log.info("method : {}", requestWrapper.getMethod());
        log.info("requestUri : {}", requestWrapper.getRequestURI());
        log.info("content-Type : {}", requestWrapper.getHeader("Content-Type"));
        log.info("Authorization : {}", requestWrapper.getHeader("Authorization"));
        requestWrapper.getParameterMap().forEach((key, value) ->
            log.info("param - key : {} , value : {}", key, value)
        );

        log.info("===================");

        filterChain.doFilter(servletRequest, servletResponse);

    }
}
