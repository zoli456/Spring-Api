package org.firstspring.fifthapi.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Configuration
public class RequestLoggingConfig {

    @Bean
    public CommonsRequestLoggingFilter requestLoggingFilter() {
        CommonsRequestLoggingFilter filter = new CommonsRequestLoggingFilter();
        filter.setIncludeClientInfo(true);  // Logs client IP & session ID
        filter.setIncludeQueryString(true); // Logs query parameters
        filter.setIncludePayload(true);     // Logs request body
        filter.setIncludeHeaders(true);     // Logs headers
        filter.setMaxPayloadLength(10000);  // Limits body size (to prevent large logs)
        return filter;
    }
}
