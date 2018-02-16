package org.apache.directory.server.vgalpartition;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SimpleEmailValidator implements IEmailValidator {
	
	public static final Pattern VALID_EMAIL_ADDRESS_REGEX = Pattern
			.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,100}$", Pattern.CASE_INSENSITIVE);
	
	@Override
	public boolean validate(String email) {
		Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(email);
		return matcher.find();
	}

	
	
}
