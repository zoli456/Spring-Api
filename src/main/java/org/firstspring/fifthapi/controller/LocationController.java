package org.firstspring.fifthapi.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class LocationController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/ip-coordinates")
    public ResponseEntity<String> getCoordinates(@RequestParam(value = "ip", required = false) String ip) {
        String url = (ip != null) ? "https://ipinfo.io/" + ip + "/json" : "https://ipinfo.io/json";
        Map<String, Object> response = restTemplate.getForObject(url, Map.class);

        if (response != null && response.containsKey("loc")) {
            return ResponseEntity.ok("Coordinates: " + response.get("loc"));
        } else {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Unable to retrieve coordinates.");
        }
    }
}