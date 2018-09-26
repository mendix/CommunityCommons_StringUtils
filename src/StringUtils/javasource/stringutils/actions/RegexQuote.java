// This file was generated by Mendix Modeler.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package stringutils.actions;

import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import stringutils.StringUtils;

/**
 * Escapes a string value so that it can be used literally with Mendix build-in regex replacement functions. 
 * e.g. *star results in \Q*star\E
 */
public class RegexQuote extends CustomJavaAction<String>
{
	private String unquotedLiteral;

	public RegexQuote(IContext context, String unquotedLiteral)
	{
		super(context);
		this.unquotedLiteral = unquotedLiteral;
	}

	@Override
	public String executeAction() throws Exception
	{
		// BEGIN USER CODE
		return StringUtils.regexQuote(unquotedLiteral);
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@Override
	public String toString()
	{
		return "RegexQuote";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
