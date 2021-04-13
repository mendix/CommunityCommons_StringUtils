package system;

import com.mendix.core.actionmanagement.IActionRegistrator;

public class UserActionsRegistrar
{
  public void registerActions(IActionRegistrator registrator)
  {
    registrator.bundleComponentLoaded();
    registrator.registerUserAction(objecthandling.actions.clone.class);
    registrator.registerUserAction(objecthandling.actions.commitInSeparateDatabaseTransaction.class);
    registrator.registerUserAction(objecthandling.actions.copyAttributes.class);
    registrator.registerUserAction(objecthandling.actions.createObjectListFromObject.class);
    registrator.registerUserAction(objecthandling.actions.deepClone.class);
    registrator.registerUserAction(objecthandling.actions.deleteAll.class);
    registrator.registerUserAction(objecthandling.actions.deleteInSeparateTransaction.class);
    registrator.registerUserAction(objecthandling.actions.deleteWithoutEvents.class);
    registrator.registerUserAction(objecthandling.actions.EndTransaction.class);
    registrator.registerUserAction(objecthandling.actions.getCreatedByUser.class);
    registrator.registerUserAction(objecthandling.actions.getGUID.class);
    registrator.registerUserAction(objecthandling.actions.getLastChangedByUser.class);
    registrator.registerUserAction(objecthandling.actions.getOriginalValueAsString.class);
    registrator.registerUserAction(objecthandling.actions.getTypeAsString.class);
    registrator.registerUserAction(objecthandling.actions.memberHasChanged.class);
    registrator.registerUserAction(objecthandling.actions.objectHasChanged.class);
    registrator.registerUserAction(objecthandling.actions.refreshClassByObject.class);
    registrator.registerUserAction(objecthandling.actions.StartTransaction.class);
    registrator.registerUserAction(stringutils.actions.Base64Decode.class);
    registrator.registerUserAction(stringutils.actions.Base64Encode.class);
    registrator.registerUserAction(stringutils.actions.DecryptString.class);
    registrator.registerUserAction(stringutils.actions.EncryptString.class);
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
    registrator.registerUserAction(stringutils.actions.RegexTest.class);
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
    registrator.registerUserAction(unittesting.actions.FindAllUnitTests.class);
    registrator.registerUserAction(unittesting.actions.ReportStepJava.class);
    registrator.registerUserAction(unittesting.actions.RunAllUnitTestsWrapper.class);
    registrator.registerUserAction(unittesting.actions.RunUnitTest.class);
    registrator.registerUserAction(unittesting.actions.StartRemoteApiServlet.class);
    registrator.registerUserAction(unittesting.actions.StartRunAllSuites.class);
    registrator.registerUserAction(unittesting.actions.ThrowAssertionFailed.class);
  }
}
