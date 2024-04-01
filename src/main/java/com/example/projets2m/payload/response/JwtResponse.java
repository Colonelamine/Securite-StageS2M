package com.example.projets2m.payload.response;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
  private String token;
  private String refreshToken;
  private String type = "Bearer";
  private Long id;
  private String username;
  private String email;
  private List<String> roles;


  public JwtResponse(String token,   Long id, String username, String email, List<String> roles, String refreshToken) {
    this.token = token;
    this.refreshToken=refreshToken;
    this.id = id;
    this.username = username;
    this.email = email;
    this.roles = roles;
  }





}




