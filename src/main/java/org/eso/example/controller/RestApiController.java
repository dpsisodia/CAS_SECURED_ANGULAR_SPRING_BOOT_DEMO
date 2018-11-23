package org.eso.example.controller;

import java.io.IOException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.eso.example.security.CasUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class RestApiController {
    private Logger logger = LoggerFactory.getLogger(RestApiController.class);
    private static final String ENCODING = "UTF-8";
	private static final String RETURN_URL_COOKIE = "return-url";
	
	/**
	 * Non secured(PUBLIC) endpoint to fetch logged in user details.
	 */
	@RequestMapping(value = "/account")
	@ResponseBody
	public Object getAccount( HttpServletRequestWrapper request, HttpServletResponseWrapper response) throws IOException {
		Map<String,Object> result = new HashMap<>();
		String userStr = null;
		Object attr = null;
		if(SecurityContextHolder.getContext().getAuthentication() != null) {
		 Object user = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	     if(user instanceof CasUserDetails ) { 
	    	 userStr = ((CasUserDetails)user).getUsername();
	    	 attr = ((CasUserDetails)user).getCasAssertion().getPrincipal().getAttributes();
	     } 
		}
		result.put("username", userStr);
		result.put("attributes", attr);
		return result;
	}
	
	/**
	 * Secured (Protected) 
	 * If we find a return URL cookie we redirect there, otherwise we return a
	 * generic string
	 */
	@RequestMapping("/login-check")
	public Object login(HttpServletRequestWrapper request, HttpServletResponse response)
			throws IOException {

		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				Cookie cookie = cookies[i];
				if (cookie.getName().equals(RETURN_URL_COOKIE)) {
					String url = URLDecoder.decode(cookie.getValue(), ENCODING);
					response.sendRedirect(url);
					return null;
				}
			}
		}

		// Something went wrong, we shouldn't be here in principle
		String msg = "Found " +
				(cookies == null ? "no" : cookies.length) +
				" cookies; no cookies named " + RETURN_URL_COOKIE;
		logger.warn( msg );
		return "Nothing here";
	}

	/**
	 * Non secured(PUBLIC) endpoint to fetch logged in user details.
	 */
	@RequestMapping(value = "/user")
	@ResponseBody
	public Object getUser() throws IOException {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof String) { // to prevent json parse error on client while going as unanimous user
            return "{}";
        }
        return principal;
	}
}
