package com.zybio.clouddesk.interceptor;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.zybio.clouddesk.config.JwtConfig;
import com.zybio.clouddesk.ldap.PersonRepo;
import com.zybio.clouddesk.pojo.Person;
import io.jsonwebtoken.Claims;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
public class TokenInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtConfig jwtConfig;

    @Autowired
    private PersonRepo personRepo;

    private final LoadingCache<String,String> tokenCache = Caffeine.newBuilder()
            .expireAfterWrite(7200, TimeUnit.SECONDS)
            .build(this::getJobNumber);

    @Override
    public boolean preHandle(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Object handler) throws TokenExpiredException {

        /** 地址过滤 */
        String uri = request.getRequestURI() ;
        if (uri.contains("/login")){
            return true ;
        }
        /** Token 验证 */
        String token = request.getHeader(jwtConfig.getHeader());
        if(StringUtils.isEmpty(token)){
            token = request.getParameter(jwtConfig.getHeader());
        }
        if(StringUtils.isEmpty(token)){
            throw new TokenExpiredException(jwtConfig.getHeader()+ "不能为空", LocalDateTime.now().toInstant(ZoneOffset.of("+08:00")));
        }
        String bearerToken = token.replace("Bearer","");


        List<String> manager = List.of(jwtConfig.getManager());


        Claims claims;

        try{
            claims = jwtConfig.getTokenClaim(bearerToken);
            if(claims == null || jwtConfig.isTokenExpired(claims.getExpiration())){
                throw new TokenExpiredException(jwtConfig.getHeader() + "失效，请重新登录。",LocalDateTime.now().toInstant(ZoneOffset.of("+08:00")));
            }
        }catch (Exception e){
            throw new TokenExpiredException(jwtConfig.getHeader() + "失效，请重新登录。",LocalDateTime.now().toInstant(ZoneOffset.of("+08:00")));
        }

//        /* 设置 identityId 用户身份ID*/
//        request.setAttribute("identityId", claims.getSubject());
//        if (manager.contains(claims.getSubject())){
//            request.setAttribute("roles", RolesEnum.ADMIN.getValue());
//        }else{
//            request.setAttribute("roles",RolesEnum.USER.getValue());
//        }
        String userName = claims.getSubject();
        request.setAttribute("jobNumber",tokenCache.get(userName));
        return true;
    }

    private String getJobNumber(String userName){
        List<Person> personList = personRepo.searchLdapUser(userName);
        if (!personList.isEmpty()){
            return personList.get(0).getEmployeeID();
        }else{
            return "null";
        }
    }
}
