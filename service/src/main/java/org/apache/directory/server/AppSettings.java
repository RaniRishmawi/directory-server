package org.apache.directory.server;

public class AppSettings {
	
	private String suffixDn;
	private String vgalClientCertificateThumbprint;
	private String vgalProxyWsdlUrl;
	
	public AppSettings(String suffixDn,
			String cgalClientCertificateThumbprint, 
			String vgalProxyWsdlUrl) {
		super();
		this.suffixDn = suffixDn;
		this.vgalClientCertificateThumbprint = cgalClientCertificateThumbprint;
		this.vgalProxyWsdlUrl = vgalProxyWsdlUrl;
	}
	
	public String getSuffixDn() {
		return suffixDn;
	}

	public String getVgalClientCertificateThumbprint() {
		return vgalClientCertificateThumbprint;
	}
	
	public String getVgalProxyWsdlUrl() {
		return vgalProxyWsdlUrl;
	}
}
