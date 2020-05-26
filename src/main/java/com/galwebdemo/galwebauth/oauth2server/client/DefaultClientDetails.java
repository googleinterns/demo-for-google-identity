package com.galwebdemo.galwebauth.oauth2server.client;


import com.galwebdemo.galwebauth.oauth2server.ClientDetails;
import org.springframework.security.core.GrantedAuthority;

import java.util.*;

// the default clientDetails implementation
public class DefaultClientDetails implements ClientDetails {

	private static final long serialVersionUID = 3L;

	private int accessTokenValiditySeconds =  60 * 60 * 12;

	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30;

	private String clientId;

	private String clientSecret;

	private Set<String> resourceIds = Collections.emptySet();

	private Set<String> scope = Collections.emptySet();

	private Set<String> authorizedGrantTypes = Collections.emptySet();

	private Set<String> redirectUris;

	private List<GrantedAuthority> authorities = Collections.emptyList();

	private Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();

	public DefaultClientDetails() {
	}

	public DefaultClientDetails(ClientDetails clientDetails) {
		this();
		setAuthorities(clientDetails.getAuthorities());
		setAuthorizedGrantTypes(clientDetails.getAuthorizedGrantTypes());
		setClientId(clientDetails.getClientId());
		setClientSecret(clientDetails.getClientSecret());
		setRedirectUri(clientDetails.getRedirectUri());
		setScope(clientDetails.getScope());
	}

	public DefaultClientDetails(String clientId, Set<String> resourceIds, String clientSecret, Set<String> scopes, Set<String> grantTypes, List<GrantedAuthority> authorities, Set<String> redirectUris) {

		this.clientId = clientId;

		this.clientSecret = clientSecret;

		this.scope = scopes;

		//default setting
		this.authorizedGrantTypes = grantTypes == null ? new HashSet<String>(Arrays.asList("authorization_code", "refresh_token")) : grantTypes;

		this.authorities = authorities == null ? this.authorities : authorities;

		this.resourceIds = resourceIds == null ? this.resourceIds : resourceIds;

		this.redirectUris = redirectUris;

	}

	//clientId
	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	//clientSecret

	public boolean isSecretRequired() {
		return this.clientSecret != null;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	//scopes

	public boolean isScoped() {
		return this.scope != null && !this.scope.isEmpty();
	}

	public Set<String> getScope() {
		return scope;
	}

	public void setScope(Collection<String> scope) {
		this.scope = scope == null ? Collections.<String> emptySet() : new LinkedHashSet<String>(scope);
	}

	//resourceIds
	public Set<String> getResourceIds() { return resourceIds; }

	public void setResourceIds(Collection<String> resourceIds) {
		this.resourceIds = resourceIds == null ? Collections.<String> emptySet() : new LinkedHashSet<String>(resourceIds);
	}

	//grantTypes

	public Set<String> getAuthorizedGrantTypes() {
		return authorizedGrantTypes;
	}

	public void setAuthorizedGrantTypes(Collection<String> authorizedGrantTypes) {
		this.authorizedGrantTypes = new LinkedHashSet<String>(authorizedGrantTypes);
	}

	//redirectUris

	public Set<String> getRedirectUri() {
		return redirectUris;
	}

	public void setRedirectUri(Set<String> redirectUris) {
		this.redirectUris = redirectUris == null ? null : new LinkedHashSet<String>(redirectUris);
	}

	//authorities

	public Collection<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
		this.authorities = new ArrayList<GrantedAuthority>(authorities);
	}

	//additional information

	public Map<String, Object> getAdditionalInformation() { return additionalInformation; }


	//validitySeconds
	@Override
	public Integer getAccessTokenValiditySeconds() {
		return accessTokenValiditySeconds;
	}

	@Override
	public Integer getRefreshTokenValiditySeconds() {
		return refreshTokenValiditySeconds;
	}

	public void addAdditionalInformation(String key, Object value) {
		this.additionalInformation.put(key, value);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((authorities == null) ? 0 : authorities.hashCode());
		result = prime * result + ((authorizedGrantTypes == null) ? 0 : authorizedGrantTypes.hashCode());
		result = prime * result + ((clientId == null) ? 0 : clientId.hashCode());
		result = prime * result + ((clientSecret == null) ? 0 : clientSecret.hashCode());
		result = prime * result + ((redirectUris == null) ? 0 : redirectUris.hashCode());
		result = prime * result + ((resourceIds == null) ? 0 : resourceIds.hashCode());
		result = prime * result + ((scope == null) ? 0 : scope.hashCode());
		result = prime * result + ((additionalInformation == null) ? 0 : additionalInformation.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DefaultClientDetails other = (DefaultClientDetails) obj;

		if (!Objects.equals(authorities , other.authorities))
			return false;
		if (!Objects.equals(authorizedGrantTypes , other.authorizedGrantTypes))
			return false;
		if (!Objects.equals(clientId , other.clientId))
			return false;
		if (!Objects.equals(clientSecret , other.clientSecret))
			return false;
		if (!Objects.equals(redirectUris , other.redirectUris))
			return false;
		if (!Objects.equals(resourceIds , other.resourceIds))
			return false;
		if (!Objects.equals(scope ,other.scope))
			return false;
		if (!Objects.equals(additionalInformation , other.additionalInformation))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "DefaultClientDetails [clientId=" + clientId + ", clientSecret="
				+ clientSecret + ", scope=" + scope + ", resourceIds="
				+ resourceIds + ", authorizedGrantTypes="
				+ authorizedGrantTypes + ", registeredRedirectUris="
				+ redirectUris + ", authorities=" + authorities
				+ ", additionalInformation="
				+ additionalInformation + "]";
	}

}
