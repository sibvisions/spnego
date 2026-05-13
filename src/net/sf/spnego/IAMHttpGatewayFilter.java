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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import net.sourceforge.spnego.SpnegoHttpFilter;
import net.sourceforge.spnego.Strings;

/**
 * Be sure to specify this filter (IAMHttpGatewayFilter) 
 * <b>BEFORE</b> the <code>IAMUserGatewayFilter</code>.
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
 * The two example classes (IAMHttpGatewayFilter and IAMUserGatewayFilter) is 
 * only meant to be illustrative. 
 * Feel free to use these two example classes as an inspiration on how 
 * you can make your implementation more robust.
 * </p>
 * 
 * <p>
 * <b>Implementation Note:</b>
 * </p>
  * <p>
 * The corresponding filter-mapping for this filter (IAMHttpGatewayFilter) must be specified 
 * <b>BEFORE</b> the filter-mapping for the <code>IAMUserGatewayFilter</code>.
 * </p>
 * 
 * @author Darwin V. Felix
 *
 */
public class IAMHttpGatewayFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(IAMHttpGatewayFilter.class.getName());

    private transient String iamHeaderName = "x-iam-user";
    private final transient Set<String> iamGatewayServers = new HashSet<>();

    /*
     * https://spnego.sourceforge.net
     * we prefer SPNEGO since http headers are easily spoofed 
     */
    private final transient SpnegoHttpFilter spnego = new SpnegoHttpFilter();

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {

        LOGGER.info("::init");

        this.spnego.init(filterConfig);

        // name of http header that the iam gateway will populate with the user's username
        final String httpHeaderName = filterConfig.getInitParameter("iam.http.header.name");

        // comma separated list of iam gateway IP addresses (servers)
        final String gatewayServers = filterConfig.getInitParameter("iam.gateway.servers");

        // provide a default if one is not provided in the web.xml file
        if (!Strings.isBlank(httpHeaderName)) {
            iamHeaderName = httpHeaderName;
        }

        // split IP addresses on commas
        if (null != gatewayServers) {
            Arrays.asList(gatewayServers.split("\\s*,\\s*")).stream()
                    .forEach((ip) -> iamGatewayServers.add(ip.trim()));
        }

        // don't check IP address if we allow requests from localhost
        if (Boolean.parseBoolean(filterConfig.getInitParameter("spnego.allow.localhost"))) {
            iamGatewayServers.add("127.0.0.1"); // NOPMD
            iamGatewayServers.add("0:0:0:0:0:0:0:1"); // NOPMD
            iamGatewayServers.add("::1"); // NOPMD            
        }
    }

    @Override
    public void destroy() {
        iamHeaderName = "x-iam-user";
        iamGatewayServers.clear();
        this.spnego.destroy();
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response
            , final FilterChain chain) throws IOException, ServletException {

        LOGGER.fine("::doFilter");

        // this is the part where it opens up applications to 
        // username spoofing if using headers instead of spnego
        final String iamUser = ((HttpServletRequest) request).getHeader(iamHeaderName);
        
        // perform Kerberos auth if (iamHeaderName) header is null or empty (SPNEGO/Kerberos is preferred)
        if (Strings.isBlank(iamUser)) {
            this.spnego.doFilter(request, response, chain);
        } else {
            final String remoteAddress = request.getRemoteAddr();

            if (iamGatewayServers.contains(remoteAddress)) {
                LOGGER.fine("::doFilter (skipped Kerberos) username retrieved from http header");
                chain.doFilter(request, response);
            } else {
                LOGGER.severe(String.format("::doFilter remoteAddress=%1$s", remoteAddress));
                throw new IllegalArgumentException("HTTP Request not from a valid IAM Gateway Server");
            }
        }
    }
}
