import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class UrlSigner {




    // Note: Generally, you should store your private key someplace safe
    // and read them into your code

//  private String keyString = configProperties.getKeyString();

    // The URL shown in these examples must be already
    // URL-encoded. In practice, you will likely have code
    // which assembles your URL from user or web service input
    // and plugs those values into its parameters.
    //private static String urlString = "http://maps.googleapis.com/maps/api/geocode/json?latlng=11.02382,79.83201&sensor=true&client=gme-spoorstechnology";

    // This variable stores the binary key, which is computed from the string (Base64) key
    private static byte[] key;

    public UrlSigner() {

    }

//    public static String getSignedUrl(String body, String keyString) throws IOException,
//                InvalidKeyException, NoSuchAlgorithmException, URISyntaxException {
//
//            // Convert the string to a URL so we can parse it
//            //URL url = new URL(urlString);
//
//            UrlSigner signer = new UrlSigner(keyString);
//            String request = signer.signRequest(body,keyString);
//
//            Log.d("Signed URL :",request);
//            return request;
//        }

    public static String getSignedUrl(String urlString,String body,String keyString) throws IOException,
            InvalidKeyException, NoSuchAlgorithmException, URISyntaxException {

        URL url = new URL(urlString);
        UrlSigner signer = new UrlSigner(keyString);
        String request = signer.signRequest(url.getPath(),url.getQuery(),body,keyString);
//    String request = signer.signRequest(body,keyString);

//        System.out.println("Signed URL :" + request);
        return request;
    }

    public UrlSigner(String keyString) throws IOException {
        keyString = keyString.replace('-', '+');
        keyString = keyString.replace('_', '/');
//        System.out.println("Key: " + keyString);
        this.key = Base64.decode(keyString);
    }

    public String signRequest(String path,String query,String body, String keyString) throws NoSuchAlgorithmException,
            InvalidKeyException, UnsupportedEncodingException, URISyntaxException {

        String resource = path + query + body + keyString;
        SecretKeySpec sha1Key = new SecretKeySpec(key, "HmacSHA1");

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(sha1Key);

        // compute the binary signature for the request
        byte[] sigBytes = mac.doFinal(resource.getBytes());

        // base 64 encode the binary signature
        String signature = Base64.encodeBytes(sigBytes);

        // convert the signature to 'web safe' base 64
        signature = signature.replace('+', '-');
        signature = signature.replace('/', '_');

        return signature;
    }

    /*public UrlSigner(String keyString) throws IOException {
        // Convert the key from 'web safe' base 64 to binary
        keyString = keyString.replace('-', '+');
        keyString = keyString.replace('_', '/');
        Log.d("Key: ",keyString);
        this.key = Base64.decode(keyString);
    }
*/
    public String signRequest(String body, String query) throws NoSuchAlgorithmException,
            InvalidKeyException, UnsupportedEncodingException, URISyntaxException {

        // Retrieve the proper URL components to sign
        //String resource = path + '?' + query;
        //String resourceReq = path + '?' + query + body;
        String resource = body + query;
        // Get an HMAC-SHA1 signing key from the raw key bytes
        SecretKeySpec sha1Key = new SecretKeySpec(key, "HmacSHA1");

        // Get an HMAC-SHA1 Mac instance and initialize it with the HMAC-SHA1 key
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(sha1Key);

        // compute the binary signature for the request
        byte[] sigBytes = mac.doFinal(resource.getBytes());

        // base 64 encode the binary signature
        String signature = Base64.encodeBytes(sigBytes);

        // convert the signature to 'web safe' base 64
        signature = signature.replace('+', '-');
        signature = signature.replace('/', '_');

        return signature;
    }
}
