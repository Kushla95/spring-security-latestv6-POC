package com.zkteco.security.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	private static final String SECRET_KEY="ea35e52611a19aac9451695554c90432c25dda438a284";
	
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	public<T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	
	public String generateToken(UserDetails userDetails) {
		return generateToken(new HashMap<>(), userDetails);
	}
	
	public String generateToken(
			Map<String, Object> extraClaims,
			UserDetails userDetails
			) {
//		return Jwts.builder()
//			      .setClaims(extraClaims)
//			      .setSubject(userDetails.getUsername())
//			      .setIssuedAt(new Date(System.currentTimeMillis()))
//			      .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
//			      .signWith(getSignInKey(),SignatureAlgorithm.HS256)
//			      .compact();
		return Jwts.builder()
			      .claims(extraClaims)
			      .subject(userDetails.getUsername())
			      .issuedAt(new Date(System.currentTimeMillis()))
			      .expiration(new Date(System.currentTimeMillis()+1000*60*24))
			      .signWith(getSignInKey(), Jwts.SIG.HS256)
			      .compact();
	}
	
	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username=extractUsername(token);
		return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
		
	}
	
	private Boolean isTokenExpired(String token) {
        return ((Date) extractExpiration(token)).before(new Date());
    }

	private Object extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	private Claims extractAllClaims(String token) {
		return Jwts
				.parser()
				.verifyWith(getSignInKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
				
	}

	private SecretKey getSignInKey() {
		// byte[] keyBytes=Decoders.BASE64.decode(SECRET_KEY);
		// return Keys.hmacShaKeyFor(keyBytes);
		return SIG.HS256.key().build();
	}

}
