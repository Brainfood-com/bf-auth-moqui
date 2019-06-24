package bf.auth;

import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.moqui.Moqui;
import org.moqui.entity.EntityValue;

public class AuthProxyFilter implements Filter {
    protected final static Logger logger = LoggerFactory.getLogger(AuthProxyFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        AuthProxyTool authProxyTool = Moqui.getExecutionContextFactory().getTool("AuthProxy", AuthProxyTool.class);
        String username;
        try {
            username = authProxyTool.decodeAuthorization(request.getHeader("Authorization"));
        } catch (GeneralSecurityException e) {
            throw (ServletException) new ServletException(e.getMessage()).initCause(e);
        }
        if (username != null) {
            AuthProxyTool.shiroRunAs(username, request.getSession(), () -> chain.doFilter(request, response));
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {
    }
}
