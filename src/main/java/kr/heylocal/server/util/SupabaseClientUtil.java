package kr.heylocal.server.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

@Component
@Slf4j
public class SupabaseClientUtil {
    private final String PREFER = "return=representation";
    private final String BASE_URL = "https://rlqdtdrozvbvmkobapnc.supabase.co";
//    private final String BASE_URL = "https://ssiexjrlplmuftarrfjg.supabase.co";

    @Value("${supabase.api.key}")
    private String API_KEY;

    private final WebClient webClient = WebClient.create(BASE_URL);

    public <T> T callSupabaseApi(String uri, HttpMethod method, Map<String,String> body, ParameterizedTypeReference<T> responseDtoClass) {
        return webClient.method(method)
                .uri(uri)
                .header("Authorization", "Bearer " + API_KEY)
                .header("Prefer", PREFER)
                .header("apikey", API_KEY)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(responseDtoClass)
                .block();
    }
}
