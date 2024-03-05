package com.gaurav.service;

import com.gaurav.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    private final String SECRET_KEY="dfd2f46322c53ee7495dc784cb9fef696c84fc4e3bb0ed1a47f37455d043f93f";


    //to get userName from token
    public String getUserName(String token){
        return extractClaim(token,Claims::getSubject);
    }

    //to extract all claims
    public Claims extractAllClaims(String token){
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    //to extract a particular claim from claims
    //we are keeping the method return type generic

    public <T> T extractClaim(String token, Function<Claims,T>resolver){
        Claims claims=extractAllClaims(token);
return  resolver.apply(claims);

    }
    //to generate token
public String generateToken(User user){
    String token= Jwts
            .builder()
            //subject is our userName
            .subject(user.getUsername())
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis()+20*60*1000))
            .signWith(getSignInKey())
            .compact();

return token;
}

public SecretKey getSignInKey(){
    byte[] keyBytes= Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);

}


public boolean isValidToken(String token, UserDetails user){
        String username=getUserName(token);
return username.equals(user.getUsername()) && !isNotExpired(token);

    }
    public boolean isNotExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

}
