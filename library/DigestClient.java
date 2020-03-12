import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.bind.DatatypeConverter;

public class DigestClient{
  private final String host;
  private final int portNum;
  private static final String method = "GET";
  private static final String version = "HTTP/1.1";
  private final String uri;
  private final String username;
  private final String password;

  private static final String CRLF = "\r\n";
  private static final Pattern digestPattern = Pattern.compile("^WWW-Authenticate:\\s?Digest\\s+realm=\"(?<realm>.+)\",\\s*nonce=\"(?<nonce>[^\\s]+)\",\\s*algorithm=(?<algorithm>[^\\s]+),\\s*qop=\"(?<qop>[^\\s]+)\"\\s*$");

  public DigestClient(String host, int portNum, String uri, String username, String password){
    this.host = host;
    this.portNum = portNum;
    this.uri = uri;
    this.username = username;
    this.password = password;
  }

  public void send(String[] args){
    Socket socket = null;
    BufferedReader reader = null;
    BufferedWriter writer = null;
    try{
      socket = new Socket(host, portNum);
    }catch(IOException e){
      e.printStackTrace();
    }

    try{
      reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
    }catch(IOException e){
      e.printStackTrace();
    }

    try{
      sendCommonMessage(writer);
      writer.write(CRLF);
      writer.flush();
    }catch(IOException e){
      e.printStackTrace();
    }

    String realm = null;
    String qop = null;
    String algorithm = null;
    String nonce = null;

    try{
      String line = null;
      Matcher matcher = null;
      while((line = reader.readLine()) != null){
        System.out.println(line);
        matcher = digestPattern.matcher(line);
        if(!matcher.matches()) continue;

        realm = matcher.group("realm");
        qop = matcher.group("qop");
        algorithm = matcher.group("algorithm");
        nonce = matcher.group("nonce");
      }
    }catch(IOException e){
      e.printStackTrace();
    }

    String a1 = username + ":" + realm + ":" + password;
    String a2 = method + ":" + uri;
    String nc = "00000001";
    String cnonce = "abcdefg0123456";

    try{
      a1 = digest(a1, algorithm);
    }catch(NoSuchAlgorithmException e){
      e.printStackTrace();
    }

    try{
      a2 = digest(a2, algorithm);
    }catch(NoSuchAlgorithmException e){
      e.printStackTrace();
    }

    String response = a1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + a2;
System.out.println(response);
    try{
      response = digest(response, algorithm);
    }catch(NoSuchAlgorithmException e){
      e.printStackTrace();
    }System.out.println(response);

    try{
      socket = new Socket(host, portNum);
      reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
    }catch(IOException e){
      e.printStackTrace();
    }

    try{
      sendCommonMessage(writer);
      writer.write("Authorization: Digest username=\"");
      writer.write(username);
      writer.write("\", realm=\"");
      writer.write(realm);
      writer.write("\", nonce=\"");
      writer.write(nonce);
      writer.write("\", uri=\"");
      writer.write(uri);
      writer.write("\", algorithm=");
      writer.write(algorithm);
      writer.write(", response=\"");
      writer.write(response);
      writer.write("\", qop=");
      writer.write(qop);
      writer.write(", nc=");
      writer.write(nc);
      writer.write(", cnonce=\"");
      writer.write(cnonce);
      writer.write("\"");
      writer.write(CRLF);
      writer.write(CRLF);
      writer.flush();
    }catch(IOException e){
      e.printStackTrace();
    }

    try{
      String line = null;
      while((line = reader.readLine()) != null && !line.isEmpty()){
        System.out.println(line);
      }

      while((line = reader.readLine()) != null){
        System.out.println(line);
      }
    }catch(IOException e){
      e.printStackTrace();
    }
  }

  public static String digest(String plaintext, String algorithm) throws NoSuchAlgorithmException{
    return DatatypeConverter.printHexBinary(MessageDigest.getInstance(algorithm).digest(plaintext.getBytes())).toLowerCase();
  }

  private void sendCommonMessage(BufferedWriter writer) throws IOException{
    writer.write(method + " " + uri + " " + version + CRLF);
    writer.write("Host: " + host + CRLF);
    writer.write("Connection: keep-alive" + CRLF);
    writer.write("User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.162 Safari/535.19" + CRLF);
    writer.write("Accept: text/html,application/xhtml+xml, application/xml;q=0.9,*/*;q=0.8" + CRLF);
    writer.write("Accept-Encoding: gzip,deflate,sdch" + CRLF);
    writer.write("Accept-Language: ja,en-US;q=0.8,en;q=0.6"+ CRLF);
    writer.write("Accept-Charset: Shift-JIS,utf-8;q=0.7,*;q=0.3" + CRLF);
  }
}

