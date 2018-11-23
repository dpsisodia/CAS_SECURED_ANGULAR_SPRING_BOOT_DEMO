package org.eso.example.security;

import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CasUserDetails implements UserDetails {

    private static final long serialVersionUID = 3664505225649994626L;

    private String userid;

    private Collection<? extends GrantedAuthority> authorities;

    private List<String> roles = new ArrayList<>();

    /**
     * CAS assertion has empty attributes if CAS protocol v 2.0 is used. Use v 3.0 instead (p3 endpoint)
     */
    private Assertion casAssertion;

    /**
     * @param user
     * @param userFactory
     */
    public CasUserDetails(String userid, Collection<? extends GrantedAuthority> authorities, Assertion assertion) {
        this.userid = userid;
        this.authorities = authorities;
        casAssertion = assertion;
        for (GrantedAuthority authority : authorities) {
            this.roles.add(authority.getAuthority());
        }
}

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return userid;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public Assertion getCasAssertion() {
        return casAssertion;
    }
}
