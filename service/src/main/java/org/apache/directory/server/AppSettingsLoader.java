package org.apache.directory.server;

import java.io.File;

import org.apache.commons.configuration2.XMLConfiguration;
import org.apache.commons.configuration2.builder.fluent.Configurations;
import org.apache.commons.configuration2.ex.ConfigurationException;

public class AppSettingsLoader {


	public AppSettings Load(String fileLocation){
		
		Configurations configs = new Configurations();
        String suffixDn = "SuffixDn";
        String vgalClientCertificateThumbprint = "";
        String vgalProxyWsdlUrl = null;
        try
        {
            XMLConfiguration config = configs.xml(new File(fileLocation));
            
            suffixDn = config.getString("SuffixDn");
            vgalClientCertificateThumbprint = config.getString("UserCertificateThumbprint");
            vgalProxyWsdlUrl = config.getString("VgalProxyWsdlUrl");
        }
        catch (ConfigurationException cex)
        {
        	cex.getCause();
        }
        
        return new AppSettings(suffixDn,
        		vgalClientCertificateThumbprint,
        		vgalProxyWsdlUrl);
	}
}
