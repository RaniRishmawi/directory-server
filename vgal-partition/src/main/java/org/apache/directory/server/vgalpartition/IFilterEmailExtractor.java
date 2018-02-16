package org.apache.directory.server.vgalpartition;

import org.apache.directory.api.ldap.model.filter.ExprNode;

public interface IFilterEmailExtractor {

	String Extract(ExprNode exprNode);
}
