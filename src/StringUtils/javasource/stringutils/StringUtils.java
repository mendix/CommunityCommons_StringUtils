package stringutils;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.text.MutableAttributeSet;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.parser.ParserDelegator;

import org.apache.commons.lang3.RandomStringUtils;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableMap;
import com.mendix.systemwideinterfaces.MendixRuntimeException;

import stringutils.proxies.SanitizerPolicy;
import static stringutils.proxies.SanitizerPolicy.BLOCKS;
import static stringutils.proxies.SanitizerPolicy.FORMATTING;
import static stringutils.proxies.SanitizerPolicy.IMAGES;
import static stringutils.proxies.SanitizerPolicy.LINKS;
import static stringutils.proxies.SanitizerPolicy.STYLES;
import static stringutils.proxies.SanitizerPolicy.TABLES;

public class StringUtils
{

	public static final String	HASH_ALGORITHM	= "SHA-256";
	
	static final Map<String, PolicyFactory> SANITIZER_POLICIES = new ImmutableMap.Builder<String, PolicyFactory>()
			.put(BLOCKS.name(), Sanitizers.BLOCKS)
			.put(FORMATTING.name(), Sanitizers.FORMATTING)
			.put(IMAGES.name(), Sanitizers.IMAGES)
			.put(LINKS.name(), Sanitizers.LINKS)
			.put(STYLES.name(), Sanitizers.STYLES)
			.put(TABLES.name(), Sanitizers.TABLES)
			.build();
	
	public static String hash(String value, int length) throws NoSuchAlgorithmException, DigestException {
		byte[] inBytes = value.getBytes(StandardCharsets.UTF_8);
		byte[] outBytes = new byte[length];

		MessageDigest alg = MessageDigest.getInstance(HASH_ALGORITHM);
		alg.update(inBytes);

		alg.digest(outBytes, 0, length);

		StringBuilder hexString = new StringBuilder();
		for (int i = 0; i < outBytes.length; i++) {
			String hex = Integer.toHexString(0xff & outBytes[i]);
			if (hex.length() == 1) {
				hexString.append('0');
			}
			hexString.append(hex);
		}

		return hexString.toString();
	}
	
	public static String regexReplaceAll(String haystack, String needleRegex,
			String replacement)
	{
		Pattern pattern = Pattern.compile(needleRegex);
		Matcher matcher = pattern.matcher(haystack);
		return matcher.replaceAll(replacement);
	}

	public static boolean regexTest(String value, String regex)
	{
		return Pattern.matches(regex, value);
	}

	public static String leftPad(String value, Long amount, String fillCharacter)
	{
		if (fillCharacter == null || fillCharacter.length() == 0) {
			return org.apache.commons.lang3.StringUtils.leftPad(value, amount.intValue(), " ");
		}
		return org.apache.commons.lang3.StringUtils.leftPad(value, amount.intValue(), fillCharacter);
	}
	
	public static String rightPad(String value, Long amount, String fillCharacter)
	{
		if (fillCharacter == null || fillCharacter.length() == 0) {
			return org.apache.commons.lang3.StringUtils.rightPad(value, amount.intValue(), " ");
		}
		return org.apache.commons.lang3.StringUtils.rightPad(value, amount.intValue(), fillCharacter);
	}

	public static String randomString(int length)
	{
		return org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric(length);
	}
	
	public static String regexReplaceAll(String source, String regexString, Function<MatchResult, String> replaceFunction)  {
		if (source == null || source.trim().isEmpty()) { // avoid NPE's, save CPU
			return "";
		}
	
		StringBuffer resultString = new StringBuffer();
		Pattern regex = Pattern.compile(regexString);
		Matcher regexMatcher = regex.matcher(source);
		
		while (regexMatcher.find()) {
			MatchResult match = regexMatcher.toMatchResult();
			String value = replaceFunction.apply(match); 
			regexMatcher.appendReplacement(resultString, Matcher.quoteReplacement(value));
		}
		regexMatcher.appendTail(resultString);
	
		return resultString.toString();
	}

	public static String randomHash()
	{
		return UUID.randomUUID().toString();
	}

	public static String base64Decode(String encoded) {
		if (encoded == null) {
			return null;
		}
		return new String(Base64.getDecoder().decode(encoded.getBytes()));
	}

	public static String base64Encode(String value) {
		if (value == null) {
			return null;
		}
		return Base64.getEncoder().encodeToString(value.getBytes());
	}
	
	public static String HTMLToPlainText(String html) throws IOException
	{
		if (html == null)
			return "";
		final StringBuffer result = new StringBuffer();
		
    HTMLEditorKit.ParserCallback callback = 
      new HTMLEditorKit.ParserCallback () {
        @Override
				public void handleText(char[] data, int pos) {
            result.append(data); //TODO: needds to be html entity decode?
        }
        
        @Override
        public void handleComment(char[] data, int pos) {
        	//Do nothing
        }
        
        @Override
				public void handleError(String errorMsg, int pos) {
        	//Do nothing
        }
        
        @Override
        public void handleSimpleTag(HTML.Tag tag, MutableAttributeSet a, int pos) {
        		 if (tag == HTML.Tag.BR)
        			 result.append("\r\n");
        }
        
        @Override
        public void handleEndTag(HTML.Tag tag, int pos){
     		 if (tag == HTML.Tag.P)
    			 result.append("\r\n");
        }
    };
    
    new ParserDelegator().parse(new StringReader(html), callback, true);
		
    return result.toString();
	}

	/**
	 * Returns a random strong password containing at least one number, lowercase character, uppercase character and strange character
	 * @param length
	 * @return
	 */
    public static String randomStrongPassword(int minLen, int maxLen, int noOfCAPSAlpha, int noOfDigits, int noOfSplChars) {
		if (minLen > maxLen) {
			throw new IllegalArgumentException("Min. Length > Max. Length!");
		}
		if ((noOfCAPSAlpha + noOfDigits + noOfSplChars) > minLen) {
			throw new IllegalArgumentException("Min. Length should be atleast sum of (CAPS, DIGITS, SPL CHARS) Length!");
		}
		return generateCommonLangPassword(minLen, maxLen, noOfCAPSAlpha, noOfDigits, noOfSplChars);
	}
    
    // See https://www.baeldung.com/java-generate-secure-password
 	// Implementation inspired by https://github.com/eugenp/tutorials/tree/master/core-java-modules/core-java-string-apis (under MIT license)
 	private static String generateCommonLangPassword(int minLen, int maxLen, int noOfCapsAlpha, int noOfDigits, int noOfSplChars) {
 		String upperCaseLetters = RandomStringUtils.random(noOfCapsAlpha, 65, 90, true, true);
 		String numbers = RandomStringUtils.randomNumeric(noOfDigits);
 		String specialChar = RandomStringUtils.random(noOfSplChars, 33, 47, false, false);
 		final int fixedNumber = noOfCapsAlpha + noOfDigits + noOfSplChars;
 		String totalChars = RandomStringUtils.randomAlphanumeric(minLen - fixedNumber, maxLen - fixedNumber);
 		String combinedChars = upperCaseLetters
 			.concat(numbers)
 			.concat(specialChar)
 			.concat(totalChars);
 		List<Character> pwdChars = combinedChars.chars()
 			.mapToObj(c -> (char) c)
 			.collect(Collectors.toList());
 		Collections.shuffle(pwdChars);
 		String password = pwdChars.stream()
 			.collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
 			.toString();
 		return password;
 	}

	public static String encryptString(String key, String valueToEncrypt) throws Exception
	{
		if (valueToEncrypt == null) {
			return null;
		}
		if (key == null) {
			throw new MendixRuntimeException("Key should not be empty");
		}
		if (key.length() != 16) {
			throw new MendixRuntimeException("Key length should be 16");
		}
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		SecretKeySpec k = new SecretKeySpec(key.getBytes(), "AES");
		c.init(Cipher.ENCRYPT_MODE, k);
		byte[] encryptedData = c.doFinal(valueToEncrypt.getBytes());
		byte[] iv = c.getIV();

		return Base64.getEncoder().encodeToString(iv) + ";" + Base64.getEncoder().encodeToString(encryptedData);
	}

	public static String decryptString(String key, String valueToDecrypt) throws Exception
	{
		if (valueToDecrypt == null) {
			return null;
		}
		if (key == null) {
			throw new MendixRuntimeException("Key should not be empty");
		}
		if (key.length() != 16) {
			throw new MendixRuntimeException("Key length should be 16");
		}
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		SecretKeySpec k = new SecretKeySpec(key.getBytes(), "AES");
		String[] s = valueToDecrypt.split(";");
		if (s.length < 2) //Not an encrypted string, just return the original value.
		{
			return valueToDecrypt;
		}
		byte[] iv = Base64.getDecoder().decode(s[0].getBytes());
		byte[] encryptedData = Base64.getDecoder().decode(s[1].getBytes());
		c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
		return new String(c.doFinal(encryptedData));
	}

	
	private static byte[] generateHmacSha256Bytes(String key, String valueToEncrypt) throws UnsupportedEncodingException, IllegalStateException, InvalidKeyException, NoSuchAlgorithmException {
		SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(secretKey);
		mac.update(valueToEncrypt.getBytes("UTF-8"));
		byte[] hmacData = mac.doFinal();

		return hmacData;
	}

	public static String generateHmacSha256(String key, String valueToEncrypt) {
		try {
			byte[] hash = generateHmacSha256Bytes(key, valueToEncrypt);
			StringBuilder result = new StringBuilder();
			for (byte b : hash) {
				result.append(String.format("%02x", b));
			}
			return result.toString();
		} catch (UnsupportedEncodingException | IllegalStateException | InvalidKeyException | NoSuchAlgorithmException e) {
			throw new RuntimeException("CommunityCommons::generateHmacSha256::Unable to encode: " + e.getMessage(), e);
		}
	}

	public static String generateHmacSha256Hash(String key, String valueToEncrypt) {
		try {
			return Base64.getEncoder().encodeToString(generateHmacSha256Bytes(key, valueToEncrypt));
		} catch (UnsupportedEncodingException | IllegalStateException | InvalidKeyException | NoSuchAlgorithmException e) {
			throw new RuntimeException("CommunityCommons::generateHmacSha256Hash::Unable to encode: " + e.getMessage(), e);
		}
	}
	
	public static String escapeHTML(String input) {
		return input.replace("&", "&amp;")
			.replace("<", "&lt;")
			.replace(">", "&gt;")
			.replace("\"", "&quot;")
			.replace("'", "&#39;");// notice this one: for xml "&#39;" would be "&apos;" (http://blogs.msdn.com/b/kirillosenkov/archive/2010/03/19/apos-is-in-xml-in-html-use-39.aspx)
		// OWASP also advises to escape "/" but give no convincing reason why: https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet
	}

	public static String regexQuote(String unquotedLiteral) {
		return Pattern.quote(unquotedLiteral);
	}
	
	public static String substringBefore(String str, String separator) {
		return org.apache.commons.lang3.StringUtils.substringBefore(str, separator);
	}

	public static String substringBeforeLast(String str, String separator) {
		return org.apache.commons.lang3.StringUtils.substringBeforeLast(str, separator);
	}

	public static String substringAfter(String str, String separator) {
		return org.apache.commons.lang3.StringUtils.substringAfter(str, separator);
	}

	public static String substringAfterLast(String str, String separator) {
		return org.apache.commons.lang3.StringUtils.substringAfterLast(str, separator);
	}

	public static String removeEnd(String str, String toRemove) {
		return org.apache.commons.lang3.StringUtils.removeEnd(str, toRemove);
	}

	public static String sanitizeHTML(String html, List<SanitizerPolicy> policyParams) {
		PolicyFactory policyFactory = null;

		for (SanitizerPolicy param : policyParams) {
			policyFactory = (policyFactory == null) ? SANITIZER_POLICIES.get(param.name()) : policyFactory.and(SANITIZER_POLICIES.get(param.name()));
		}

		return sanitizeHTML(html, policyFactory);
	}

	public static String sanitizeHTML(String html, PolicyFactory policyFactory) {
		return policyFactory.sanitize(html);
	}

	public static String stringSimplify(String value) {
		String normalized = Normalizer.normalize(value, Normalizer.Form.NFD);
		return normalized.replaceAll("\\p{M}", ""); // removes all characters in Unicode Mark category
	}

	public static Boolean isStringSimplified(String value) {
		return Normalizer.isNormalized(value, Normalizer.Form.NFD);
	}
	
}
