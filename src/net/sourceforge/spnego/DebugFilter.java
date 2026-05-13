package net.sourceforge.spnego;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class DebugFilter implements Filter
{
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Interface implementation
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /**
     * {@inheritDoc}
     */
    public void init(FilterConfig pConfig) throws ServletException
    {
    }

    /**
     * {@inheritDoc}
     */
    public void destroy()
    {
    }

    /**
     * {@inheritDoc}
     */
    public void doFilter(ServletRequest pRequest, ServletResponse pResponse, FilterChain pChain) throws IOException, ServletException
    {
        HttpServletRequest request = (HttpServletRequest)pRequest;
        
        String sResource = request.getRequestURI();
        
        System.out.println(sResource);
        
        for (Enumeration<?> en = request.getHeaderNames(); en.hasMoreElements();)
        {
            String headName = (String)en.nextElement();
            
            System.out.println(headName +" = " + request.getHeader(headName));
        }

        pChain.doFilter(pRequest, pResponse);
    }
    
}   // DebugFilter
