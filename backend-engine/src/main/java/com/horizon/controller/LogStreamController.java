package com.horizon.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
@RequestMapping("/api/v1/logs")
@CrossOrigin(origins = "*")
public class LogStreamController {

    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamLogs() {
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        this.emitters.add(emitter);
        emitter.onCompletion(() -> this.emitters.remove(emitter));
        emitter.onTimeout(() -> this.emitters.remove(emitter));
        return emitter;
    }

    @PostMapping
    public void ingestLog(@RequestBody Map<String, Object> logPayload) {
        String message = (String) logPayload.getOrDefault("rawMessage", "");
        String type = "NORMAL_EVENT";
        
        if (message.toLowerCase().contains("failed password") || message.toLowerCase().contains("brute force")) {
            type = "SECURITY_THREAT";
        } else if (message.toLowerCase().contains("error") || message.toLowerCase().contains("garbage")) {
            type = "SYSTEM_FAULT";
        }
        
        logPayload.put("classifiedType", type);
        logPayload.putIfAbsent("timestamp", System.currentTimeMillis());

        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(logPayload);
            } catch (IOException e) {
                emitters.remove(emitter);
            }
        }
    }
}
