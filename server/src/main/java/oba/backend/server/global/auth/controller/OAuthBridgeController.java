package oba.backend.server.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class OAuthBridgeController {

    @GetMapping("/oauth/bridge")
    public String oauthBridge() {
        return "oauth-bridge";
    }
}
