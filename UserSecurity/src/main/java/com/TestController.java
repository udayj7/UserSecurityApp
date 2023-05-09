package com;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
	
	@GetMapping("/hi")
	public String getMsg() {
		return "<h1>Welcome</h1>";
	}
	
	@GetMapping("/admin")
	public String getMsgAdmin() {
		return "<h1>Welcome my dear admin</h1>";
	}
	
	@GetMapping("/user")
	public String getMsgUser() {
		return "<h1>Welcomemy dear user or admin</h1>";
	}
}
