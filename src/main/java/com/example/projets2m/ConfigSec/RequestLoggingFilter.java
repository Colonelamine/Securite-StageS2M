package com.example.projets2m.ConfigSec;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Date;

@Component
@Order(1)
public class RequestLoggingFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Enregistrement des informations de la requête
        String url = request.getRequestURL().toString();
        String method = request.getMethod();
        String queryString = request.getQueryString();
        String remoteAddress = request.getRemoteAddr(); // Adresse IP du client
        String userAgent = request.getHeader("User-Agent");
        String protocol = request.getProtocol();
        String contentType = request.getContentType();
        String path = request.getPathInfo();

        // Adresse IP du serveur
        InetAddress inetAddress = InetAddress.getLocalHost();
        String serverIp = inetAddress.getHostAddress();

        // Récupération du username et password
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // Timestamp (temps)
        Date timestamp = new Date();

        logger.info("Request received - Timestamp: {}, URL: {}, Method: {}, Query String: {}, Remote Address: {}, Server IP: {}, User-Agent: {}, Protocol: {}, ContentType: {}, Path: {}", timestamp, url, method, queryString, remoteAddress, serverIp, userAgent, protocol, contentType, path);

        // Lecture du corps de la requête à l'aide du wrapper
        MultiReadHttpServletRequest multiReadRequest = new MultiReadHttpServletRequest(request);
        String requestBody = multiReadRequest.getBody();
        logger.info("Request Body: {}", requestBody);

        // Passer la demande enveloppée à la chaîne de filtres
        filterChain.doFilter(multiReadRequest, response);
    }
}

