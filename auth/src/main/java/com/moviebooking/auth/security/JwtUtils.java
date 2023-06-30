package com.moviebooking.auth.security;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.moviebooking.auth.exception.InvalidInputException;
import com.moviebooking.auth.model.ERole;
import com.moviebooking.auth.model.Role;
import com.moviebooking.auth.model.User;
import com.moviebooking.auth.payload.LoginRequest;
import com.moviebooking.auth.service.UserService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtUtils {

	@Value("${authentication.app.jwtSecret}")
	private String jwtSecret;

	@Value("${authentication.app.jwtExpirationMs}")
	private int jwtExpirationMs;

	@Autowired
	UserService userService;

	public String generatToken(LoginRequest loginRequest) {
		try {

			String username = loginRequest.getUsername();
			String password = loginRequest.getPassword();

			if (username == null || password == null) {
				throw new InvalidInputException("please enter valid credentials");
			}
			boolean flag = userService.loginUser(loginRequest);
			Optional<User> user = userService.getUserByUsername(username);
			List<String> roleNames = user.get().getRoles().stream().map(Role::getName).collect(Collectors.toList());
			System.out.println(roleNames.get(0));
			System.out.println("above is role");
			if (!flag) {
				throw new InvalidInputException("Invalid credentials");
			}
			String jwtToken = Jwts.builder().setSubject(username).claim("role", roleNames.get(0).toString())
					.setIssuedAt(new Date()).setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
					.signWith(SignatureAlgorithm.HS512, jwtSecret).compact();
			return jwtToken;
		} catch (InvalidInputException e) {
			throw new InvalidInputException(e.getMessage());
		}
	}

	public String getUserNameFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}

	public Claims getJwtClaims(String token) {
		Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
		return claims;
	}

	public String getRoleFromToken(String token) {
		Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
		String role = (String) claims.get("role");
		return role;
	}

	public boolean validateJwtToken(String token) {
		String authToken = null;
		String user = null;
		if (token != null && token.startsWith("Bearer ")) {
			authToken = token.substring(7);
			try {
				user = getUserNameFromJwtToken(authToken);
				System.out.println(user);
				return true;
			} catch (SignatureException e) {
				System.err.println("Invalid JWT signature: {} " + e.getMessage());

			} catch (MalformedJwtException e) {

				System.err.println("Invalid JWT signature: {} " + e.getMessage());
			} catch (ExpiredJwtException e) {

				System.err.println("JWT token is expired: {} " + e.getMessage());
			} catch (UnsupportedJwtException e) {

				System.err.println("JWT token is unsupported: {} " + e.getMessage());
			} catch (IllegalArgumentException e) {

				System.err.println("JWT claims string is empty: {} " + e.getMessage());
			}
		}
		return false;
	}

}
