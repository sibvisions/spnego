/** 
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package net.sf.spnego;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;

import net.sourceforge.spnego.Strings;

/**
 * Be sure to specify this <b>AFTER</b> the <code>SpnegoHttpSessionFilter</code>.
 * 
 * @author Darwin V. Felix
 *
 */
public class UserHttpSessionFilter implements Filter {
    
    /** logger. */
    private static final Logger LOGGER = Logger.getLogger(UserHttpSessionFilter.class.getName());
    
    private String httpSessAttribName = "spnegoAuthNuser";

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        // TODO ...?
        LOGGER.info("UserHttpSessionFilter::init");
        final String tmp = filterConfig.getInitParameter("http.sess.attib.name");
        if (!Strings.isBlank(tmp)) {
            httpSessAttribName = tmp;
        }
    }  

    @Override
    public void destroy() {
        // TODO ...?
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response
        , final FilterChain chain) throws IOException, ServletException {
        
        final String spnegoAuthNuser;
        
        final HttpServletRequest httpRequest = (HttpServletRequest) request;

        // populated by spnego filter on first request
        final String remoteUser = httpRequest.getRemoteUser();

        final HttpSession httpSession = httpRequest.getSession(false);
        
        if (!Strings.isBlank(remoteUser)) {
            
            spnegoAuthNuser = getSpnegoAuthNuser(remoteUser);
            
            if (null != httpSession) {
                LOGGER.fine("UserHttpSessionFilter::doFilter: has httpSession");
                httpRequest.getSession().setAttribute(httpSessAttribName, spnegoAuthNuser);
            } else {
                LOGGER.fine("UserHttpSessionFilter::doFilter: no httpSession");
            }

            // no remoteUser but have a session
        } else if (null != httpSession && null != httpSession.getAttribute(httpSessAttribName)) {
            LOGGER.fine("UserHttpSessionFilter::doFilter: httpSession=" + httpSession);
            spnegoAuthNuser = (String) httpSession.getAttribute("spnegoAuthNuser");
            LOGGER.fine("UserHttpSessionFilter::doFilter: spnegoAuthNuser=" + spnegoAuthNuser);
            
            // no session spnegoAuthNuser nor remoteUser
        } else {
            // check spnego.exclude.dirs before throwing exception
            //if () {
            //    
            //}
            throw new ServletException("Could not identify logged-in user: httpSession="
                    + httpSession + "; remoteUser=" + remoteUser);
        }
        
        // requirement is that getRemoteUser should return HR Employee Id (not NT account)
        final HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(httpRequest) {
            @Override
            public String getRemoteUser() {
                return spnegoAuthNuser;
            }
        };

        chain.doFilter(wrapper, response);
    }

    /*
     * This is just a silly example.
     * 
     * @param remoteUser
     * @return
     */
    private String getSpnegoAuthNuser(final String remoteUser) {
        // TODO implement logic to convert NT Login to HR Employee Id
        return remoteUser; 
    }
}
