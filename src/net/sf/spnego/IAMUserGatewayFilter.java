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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import net.sourceforge.spnego.Strings;

/**
 * Be sure to specify this filter (IAMUserGatewayFilter) 
 * <b>AFTER</b> the <code>IAMHttpGatewayFilter</code>.
 * 
 * <p>
 * Do all you can to avoid using IAM Gateways. 
 * Do not use IAM Gateways unless you absolutely have no options 
 * and someone is forcing you down this HTTP HEADER based approach to authentication.
 * </p>
 * <p>
 * Using IAM Gateways and sending usernames via an HTTP HEADER is inherently unsafe.
 * </p>
 * 
 * <p>
 * <b>Note:</b>
 * </p>
 * <p>
 * These two example classes (IAMHttpGatewayFilter and IAMUserGatewayFilter) is 
 * only meant to be illustrative. 
 * Feel free to use these two example classes as an inspiration on how 
 * you can make your implementation more robust.
 * </p>
 * 
 * <p>
 * <b>Implementation Note:</b>
 * </p>
 * 
 * <p>
 * The corresponding filter-mapping for this filter must be specified 
 * <b>AFTER</b> the filter-mapping for the <code>IAMHttpGatewayFilter</code>.
 * </p>
 * 
 * @author Darwin V. Felix
 *
 */
public class IAMUserGatewayFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(IAMUserGatewayFilter.class.getName());

    // name of the http header that the IAM gateway will use to populate user's username
    private transient String iamHeaderName = "";

    // an iam will sometimes include the realm component in the username (e.g. dfelix@athena.local)
    private transient boolean iamExcludeUserReam = true;
    
    // directories which should not be authenticated irrespective of filter-mapping.
    private final transient List<String> excludeDirs = new ArrayList<String>();

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {

        LOGGER.info("IAMUserGatewayFilter::init");

        // name of http header that the IAM gateway will populate with the user's username
        final String httpHeaderName = filterConfig.getInitParameter("iam.http.header.name");

        // remove the realm component from the returned username (if one is provided)
        final String excludeUserRealm = filterConfig.getInitParameter("iam.exclude.user.realm");

        // exclude urls/paths/dirs from auth (i.e. allow anonymous access)
        final String excludeUrls = filterConfig.getInitParameter("spnego.exclude.dirs");
        
        // provide a default if one is not provided in the web.xml file
        if (!Strings.isBlank(httpHeaderName)) {
            iamHeaderName = httpHeaderName;
        } else {
            iamHeaderName = "x-iam-user";
        }

        // default to true if filter parameter not defined/specified
        iamExcludeUserReam = (null == excludeUserRealm) ? true : Boolean.parseBoolean(excludeUserRealm);

        // user-defined list of paths/urls/dirs that does need authentication (public folders, etc.)
        if (null != excludeUrls) {
            Arrays.asList(excludeUrls.split("\\s*,\\s*")).stream().forEach((dir) -> excludeDirs.add(dir.trim()));
        }
    }

    @Override
    public void destroy() {
        iamHeaderName = "";
        iamExcludeUserReam = true;
        excludeDirs.clear();
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        LOGGER.fine("IAMUserGatewayFilter::doFilter");

        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final String remoteUser = httpRequest.getRemoteUser();

        // this is the part where it opens up applications to username spoofing if using OAG instead of spnego
        final String iamUser = httpRequest.getHeader(iamHeaderName);

        // skip authentication if resource is in the list of directories to exclude
        if (excludeDirs.size() > 0 && exclude(httpRequest.getContextPath(), httpRequest.getServletPath()
                , httpRequest.getRequestURI())) {
            
            chain.doFilter(request, response);
            return;
        } else if (null == remoteUser && (Strings.isBlank(iamUser))) {

            // this info might be helpful during debugging/troubleshooting
            LOGGER.info("IAMUserGatewayFilter::doFilter getServletPath()=" + httpRequest.getServletPath());
            LOGGER.info("IAMUserGatewayFilter::doFilter getRequestURI()=" + httpRequest.getRequestURI());
            LOGGER.info("IAMUserGatewayFilter::doFilter excludeDirs=" + excludeDirs);

            throw new IllegalArgumentException("IAM Gateway did not provide an IAM username");
        }

        final String user = (null != remoteUser) ? remoteUser : iamUser;

        // akka needs this since akka's HttpRequest api has no equivalent
        request.setAttribute(iamHeaderName, user);

        chain.doFilter(new HttpServletRequestWrapper((HttpServletRequest) request) {
            @Override
            public String getRemoteUser() {
                
                return (iamExcludeUserReam) ? user.split("@")[0] : user;
            }
        }, response);
    }

    // allow anonymous access to specific urls/paths/dirs (user-defined via web.xml)
    private boolean exclude(final String contextPath, final String servletPath, final String requestUri) {
        // each item in excludeDirs ends with a slash
        final String path = contextPath + servletPath + (servletPath.endsWith("/") ? "" : "/");

        for (String dir : this.excludeDirs) {
            if (path.startsWith(dir)) {
                return true;
            } else if (requestUri.startsWith(dir)) {
                return true;
            }
        }

        return false;
    }
}
