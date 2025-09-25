package com.kts_proof_sub_poc;

import com.google.genai.Client;
import lombok.extern.log4j.Log4j2;
import org.apache.tika.Tika;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
@Log4j2
public class BeanConfig {
    @Bean
    public Client getClient(@Value("${gemini_api_key}") String apiKey) {
        return Client.builder()
                .apiKey(apiKey)
                .build();
    }

    @Bean
    public Tika tika() {
        return new Tika();
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
