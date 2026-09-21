package system;

import com.mendix.core.actionmanagement.IActionRegistrator;

public class UserActionsRegistrar
{
  public void registerActions(IActionRegistrator registrator)
  {
    registrator.registerUserAction(stringutils.actions.Base64Decode.class);
    registrator.registerUserAction(stringutils.actions.Base64Encode.class);
    registrator.registerUserAction(stringutils.actions.GenerateHMAC_SHA256_hash.class);
    registrator.registerUserAction(stringutils.actions.GenerateHMAC_SHA256_HexDigest.class);
    registrator.registerUserAction(stringutils.actions.Hash.class);
    registrator.registerUserAction(stringutils.actions.HTMLEscape.class);
    registrator.registerUserAction(stringutils.actions.HTMLToPlainText.class);
    registrator.registerUserAction(stringutils.actions.RandomHash.class);
    registrator.registerUserAction(stringutils.actions.RandomString.class);
    registrator.registerUserAction(stringutils.actions.RandomStrongPassword.class);
    registrator.registerUserAction(stringutils.actions.RegexQuote.class);
    registrator.registerUserAction(stringutils.actions.RegexReplaceAll.class);
    registrator.registerUserAction(stringutils.actions.StringLeftPad.class);
    registrator.registerUserAction(stringutils.actions.StringLength.class);
    registrator.registerUserAction(stringutils.actions.StringRightPad.class);
    registrator.registerUserAction(stringutils.actions.StringTrim.class);
    registrator.registerUserAction(stringutils.actions.SubstringAfter.class);
    registrator.registerUserAction(stringutils.actions.SubstringAfterLast.class);
    registrator.registerUserAction(stringutils.actions.SubstringBefore.class);
    registrator.registerUserAction(stringutils.actions.SubstringBeforeLast.class);
    registrator.registerUserAction(stringutils.actions.XSSSanitize.class);
    registrator.registerUserAction(system.actions.VerifyPassword.class);
    registrator.registerUserAction(unittesting.actions.AssertUsingExpression.class);
    registrator.registerUserAction(unittesting.actions.FindAllUnitTests.class);
    registrator.registerUserAction(unittesting.actions.Initialize.class);
    registrator.registerUserAction(unittesting.actions.IsEnabled.class);
    registrator.registerUserAction(unittesting.actions.IsInitialized.class);
    registrator.registerUserAction(unittesting.actions.RegisterModelUpdateSubscriber.class);
    registrator.registerUserAction(unittesting.actions.ReportStepJava.class);
    registrator.registerUserAction(unittesting.actions.RunAllUnitTestsWrapper.class);
    registrator.registerUserAction(unittesting.actions.RunUnitTest.class);
    registrator.registerUserAction(unittesting.actions.StartRemoteApiServlet.class);
    registrator.registerUserAction(unittesting.actions.StartRunAllSuites.class);
    registrator.registerUserAction(unittesting.actions.TestRefreshRequired.class);
    registrator.registerUserAction(unittesting.actions.ThrowAssertionFailed.class);
    registrator.registerUserAction(unittesting.actions.UpdateTestSuiteCountersAndResult.class);
  }
}
