package org.apache.directory.server.vgalpartition;

import java.util.List;

import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.filter.SubstringNode;

public class FilterEmailExtractor implements IFilterEmailExtractor {

	@Override
	public String Extract(ExprNode exprNode) {

		SubstringNode sn = null;
		if (exprNode instanceof OrNode) {
			for (ExprNode ssn : ((OrNode) exprNode).getChildren()) {
				if (((SubstringNode) ssn).getAttribute().equals("mail")) {
					sn = (SubstringNode) ssn;
					break;
				}
			}
		} else if (exprNode instanceof SubstringNode) {
			sn = ((SubstringNode) exprNode);
		} else
			return null;

		String initialToken = sn.getInitial();
		List<String> anyPattern = sn.getAny();

		if (initialToken == null)
			return anyPattern.get(0);

		return initialToken;
	}

}
