package kr.heylocal.server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {
    @GetMapping("health")
    public String health(@RequestParam String test, @RequestParam String test2) {
        return "OK";
    }
}
