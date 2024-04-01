package com.example.projets2m.ConfigSec;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;


@Component
@Order(2)
public class ResponseLoggingFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(ResponseLoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Intercepter la réponse
        ResponseWrapper responseWrapper = new ResponseWrapper(response);

        // Passer la requête au filtre suivant dans la chaîne
        filterChain.doFilter(request, responseWrapper);

        // Enregistrer les informations de la réponse
        int status = responseWrapper.getStatus();
        logger.info("Response status: {}", status);

        // Enregistrer le corps de la réponse
        String responseBody = responseWrapper.getBody();
        logger.info("Response body: {}", responseBody);

        // Copier le contenu du flux de sortie intercepté dans le flux de sortie original de la réponse
        ServletOutputStream originalOutputStream = response.getOutputStream();
        responseWrapper.copyBodyToResponse(originalOutputStream);
    }

    private static class ResponseWrapper extends HttpServletResponseWrapper {
        private final ByteArrayOutputStreamWrapper byteArrayOutputStreamWrapper;
        private ServletOutputStream servletOutputStream;

        ResponseWrapper(HttpServletResponse response) {
            super(response);
            byteArrayOutputStreamWrapper = new ByteArrayOutputStreamWrapper();
        }
        void copyBodyToResponse(ServletOutputStream outputStream) throws IOException {
            byteArrayOutputStreamWrapper.writeTo(outputStream);
        }


        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            if (servletOutputStream == null) {
                servletOutputStream = new ServletOutputStreamWrapper(byteArrayOutputStreamWrapper);
            }
            return servletOutputStream;
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            throw new UnsupportedOperationException("getWriter() not supported.");
        }

        String getBody() {
            return byteArrayOutputStreamWrapper.toString();
        }
    }

    private static class ServletOutputStreamWrapper extends ServletOutputStream {
        private final ByteArrayOutputStreamWrapper byteArrayOutputStreamWrapper;

        ServletOutputStreamWrapper(ByteArrayOutputStreamWrapper byteArrayOutputStreamWrapper) {
            this.byteArrayOutputStreamWrapper = byteArrayOutputStreamWrapper;
        }

        @Override
        public void write(int b) throws IOException {
            byteArrayOutputStreamWrapper.write(b);
        }

        @Override
        public boolean isReady() {
            return false;
        }

        @Override
        public void setWriteListener(WriteListener writeListener) {

        }
    }

    private static class ByteArrayOutputStreamWrapper extends ByteArrayOutputStream {
        @Override
        public void close() throws IOException {
            super.close();
        }

    }
}
