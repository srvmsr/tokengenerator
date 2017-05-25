/*
 * javac akamai_token_v2.java
 *
 * Copyright (c) 2012, Akamai Technologies, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Akamai Technologies nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AKAMAI TECHNOLOGIES BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.regex.*;

import javax.xml.bind.DatatypeConverter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class AkamaiTokenException extends Exception {
    public AkamaiTokenException(String msg) { super(msg); }
}

class AkamaiToken {
    private static String program_name = "akamai_token_v2";
    private static String default_token_name = "hdnts";
    private static String default_acl = "/*";
    private static String default_algo = "sha256";
    private static String default_field_delimiter = "~";
    private static String default_acl_delimiter = "!";

    private static void displayHelp() {
        System.out.println("Usage: java AkamaiToken [options]");
        System.out.println("ie.");
        System.out.println("java AkamaiToken");
        System.out.println("");
        System.out.println("Options:");
        System.out.println("  --version             show program's version number and exit");
        System.out.println("  -h, --help            show this help message and exit");
        System.out.println("  -t TOKEN_TYPE, --token_type TOKEN_TYPE");
        System.out.println("                        Select a preset: (Not Supported Yet) [2.0, 2.0.2 ,PV, Debug]");
        System.out.println("  -n TOKEN_NAME, --token_name TOKEN_NAME");
        System.out.println("                        Parameter name for the new token. [Default:hdnts]");
        System.out.println("  -i IP_ADDRESS, --ip IP_ADDRESS");
        System.out.println("                        IP Address to restrict this token to.");
        System.out.println("  -s START_TIME, --start_time START_TIME");
        System.out.println("                        What is the start time. (Use now for the current time)");
        System.out.println("  -e END_TIME, --end_time END_TIME");
        System.out.println("                        When does this token expire? --end_time overrides");
        System.out.println("                        --window [Used for:URL or COOKIE]");
        System.out.println("  -w WINDOW_SECONDS, --window WINDOW_SECONDS");
        System.out.println("                        How long is this token valid for?");
        System.out.println("  -u URL, --url URL     URL path. [Used for:URL]");
        System.out.println("  -a ACCESS_LIST, --acl ACCESS_LIST");
        System.out.println("                        Access control list delimited by ! [ie. /*]");
        System.out.println("  -k KEY, --key KEY     Secret required to generate the token.");
        System.out.println("  -p PAYLOAD, --payload PAYLOAD");
        System.out.println("                        Additional text added to the calculated digest.");
        System.out.println("  -A ALGORITHM, --algo ALGORITHM");
        System.out.println("                        Algorithm to use to generate the token. (sha1, sha256,");
        System.out.println("                        or md5) [Default:sha256]");
        System.out.println("  -S SALT, --salt SALT  Additional data validated by the token but NOT");
        System.out.println("                        included in the token body.");
        System.out.println("  -I SESSION_ID, --session_id SESSION_ID");
        System.out.println("                        The session identifier for single use tokens or other");
        System.out.println("                        advanced cases.");
        System.out.println("  -d FIELD_DELIMITER, --field_delimiter FIELD_DELIMITER");
        System.out.println("                        Character used to delimit token body fields.");
        System.out.println("                        [Default:~]");
        System.out.println("  -D ACL_DELIMITER, --acl_delimiter ACL_DELIMITER");
        System.out.println("                        Character used to delimit acl fields. [Default:!]");
        System.out.println("  -x, --escape_early    Causes strings to be url encoded before being used.");
        System.out.println("                        (legacy 2.0 behavior)");
        System.out.println("  -X, --escape_early_upper");
        System.out.println("                        Causes strings to be url encoded before being used.");
        System.out.println("                        (legacy 2.0 behavior)");
        System.out.println("  -v, --verbose");
    }

    private static void displayVersion() {
        System.out.println("2.0.7");
    }

    private static String getKeyValue(final Dictionary token_config, final String key,
        final String default_value) {
        Object value = token_config.get(key);
        if (value == null) {
            return default_value;
        }
        return value.toString();
    }

    private static String escapeEarly(final Dictionary token_config, final String text) {
        String escape_early = getKeyValue(token_config, "escape_early", "false");
        String escape_early_upper = getKeyValue(token_config, "escape_early_upper", "false");
        StringBuilder new_text = new StringBuilder(text);
        try {
            if (escape_early.equalsIgnoreCase("true") ||
                escape_early_upper.equalsIgnoreCase("true")) {
                new_text = new StringBuilder(URLEncoder.encode(text, "UTF-8"));
                Pattern pattern = Pattern.compile("%..");
                Matcher matcher = pattern.matcher(new_text);
                String temp_text;
                while (matcher.find()) {
                    if (escape_early_upper.equalsIgnoreCase("true")) {
                        temp_text = new_text.substring(matcher.start(), matcher.end()).toUpperCase();
                    } else {
                        temp_text = new_text.substring(matcher.start(), matcher.end()).toLowerCase();
                    }
                    new_text.replace(matcher.start(), matcher.end(), temp_text);
                }
            }
        } catch (UnsupportedEncodingException e) {
            // Ignore any encoding errors and return the original string.
        }

        return new_text.toString();
    }

    private static void displayParameters(Dictionary token_config) {
        String escape_early = getKeyValue(token_config, "escape_early", "false");
        String escape_early_upper = getKeyValue(token_config, "escape_early_upper", "false");
        if (escape_early.equalsIgnoreCase("true") || escape_early_upper.equalsIgnoreCase("true")) {
            escape_early = "true";
        }
        System.out.println("Akamai Token Generation Parameters");
        System.out.println("    Token Type      : " + getKeyValue(token_config, "token_type", ""));
        System.out.println("    Token Name      : " + getKeyValue(token_config, "token_name", default_token_name));
        System.out.println("    Start Time      : " + getKeyValue(token_config, "start_time", ""));
        System.out.println("    Window(seconds) : " + getKeyValue(token_config, "window_seconds", ""));
        System.out.println("    End Time        : " + getKeyValue(token_config, "end_time", ""));
        System.out.println("    IP              : " + getKeyValue(token_config, "ip_address", ""));
        System.out.println("    URL             : " + getKeyValue(token_config, "url", ""));
        System.out.println("    ACL             : " + getKeyValue(token_config, "acl", default_acl));
        System.out.println("    Key/Secret      : " + getKeyValue(token_config, "key", ""));
        System.out.println("    Payload         : " + getKeyValue(token_config, "payload", ""));
        System.out.println("    Algo            : " + getKeyValue(token_config, "algo", default_algo));
        System.out.println("    Salt            : " + getKeyValue(token_config, "salt", ""));
        System.out.println("    Session ID      : " + getKeyValue(token_config, "session_id", ""));
        System.out.println("    Field Delimiter : " + getKeyValue(token_config, "field_delimiter", default_field_delimiter));
        System.out.println("    ACL Delimiter   : " + getKeyValue(token_config, "acl_delimiter", default_acl_delimiter));
        System.out.println("    Escape Early    : " + escape_early);
        System.out.println("Generating token...");
    }

    private static String getTokenIP(Dictionary token_config) {
        String ip_address = escapeEarly(token_config, getKeyValue(token_config, "ip_address", "")); 
        if (ip_address.length() > 0) {
            return "ip=" + ip_address + getKeyValue(token_config, "field_delimiter", default_field_delimiter);
        }
        return "";
    }

    private static String getTokenStartTime(Dictionary token_config) {
        String start_time = getKeyValue(token_config, "start_time", "");
        if (start_time.length() > 0) {
            return "st=" + start_time + getKeyValue(token_config, "field_delimiter", default_field_delimiter);
        }
        return "";
    }

    private static String getTokenEndTime(Dictionary token_config) {
        return "exp=" + getKeyValue(token_config, "end_time", "") + getKeyValue(token_config, "field_delimiter", default_field_delimiter);
    }

    private static String getTokenAcl(Dictionary token_config) {
        String acl = escapeEarly(token_config, getKeyValue(token_config, "acl", ""));
        if (acl.length() > 0) {
            return "acl=" + acl + getKeyValue(token_config, "field_delimiter", default_field_delimiter);
        }
        return "";
    }

    private static String getTokenSessionID(Dictionary token_config) {
        String session_id = escapeEarly(token_config, getKeyValue(token_config, "session_id", ""));
        if (session_id.length() > 0) {
            return "id=" + session_id + getKeyValue(token_config, "field_delimiter", default_field_delimiter);
        }
        return "";
    }

    private static String getTokenPayload(Dictionary token_config) {
        String payload = escapeEarly(token_config, getKeyValue(token_config, "payload", ""));
        if (payload.length() > 0) {
            return "data=" + payload + getKeyValue(token_config, "field_delimiter", default_field_delimiter);
        }
        return "";
    }

    private static String getTokenUrl(Dictionary token_config) {
        String url = escapeEarly(token_config, getKeyValue(token_config, "url", ""));
        if (url.length() > 0) {
            return "url=" + url + getKeyValue(token_config, "field_delimiter", default_field_delimiter);
        }
        return "";
    }

    private static String getTokenSalt(Dictionary token_config) {
        String salt = escapeEarly(token_config, getKeyValue(token_config, "salt", ""));
        if (salt.length() > 0) {
            return "salt=" + salt + getKeyValue(token_config, "field_delimiter", default_field_delimiter);
        }
        return "";
    }

    @SuppressWarnings("unchecked")
    public static String generateToken(Dictionary token_config) throws AkamaiTokenException {

        String algo = getKeyValue(token_config, "algo", default_algo);
        if (!algo.equalsIgnoreCase("md5") && !algo.equalsIgnoreCase("sha1") &&
            !algo.equalsIgnoreCase("sha256")) {
            throw new AkamaiTokenException("unknown algorithm");
        }

        String start_time_text = getKeyValue(token_config, "start_time", "");
        long start_time = 0;
        if (start_time_text.equalsIgnoreCase("now")) {
            start_time = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis()/1000L;
            token_config.put("start_time", Long.toString(start_time));
        } else if (start_time_text != "" ) {
            try {
                start_time = Long.parseLong(start_time_text);
            } catch (Exception e) {
                throw new AkamaiTokenException("start_time must be numeric or now");
            }
        }

        long window = Long.parseLong(getKeyValue(token_config, "window_seconds", "0"));

        String end_time_text = getKeyValue(token_config, "end_time", "");
        long end_time = 0;
        if (end_time_text.equalsIgnoreCase("now")) {
            end_time = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis()/1000L;
        } else if (end_time_text != "" ) {
            try {
                end_time = Long.parseLong(end_time_text);
            } catch (Exception e) {
                throw new AkamaiTokenException("end_time must be numeric");
            }
        } else {
            if (start_time_text != "" ) {
                end_time = start_time + window;
            } else {
                end_time = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis()/1000L + window;
            }
        }
        token_config.put("end_time", Long.toString(end_time));

        String acl = getKeyValue(token_config, "acl", "");
        String url = getKeyValue(token_config, "url", "");
        if (acl.length() < 1 && url.length() < 1) {
            throw new AkamaiTokenException("you must provide an acl or url");
        } else if (acl.length() >= 1 && url.length() >= 1) {
            throw new AkamaiTokenException("you must provide an acl or url, not both");
        }

        String key = getKeyValue(token_config, "key", "");
        if (key.length() < 1)
            throw new AkamaiTokenException("you must provide a key");

        if (getKeyValue(token_config, "verbose", "").equalsIgnoreCase("true"))
            displayParameters(token_config);

        StringBuilder new_token = new StringBuilder();
        new_token.append(getTokenIP(token_config));
        new_token.append(getTokenStartTime(token_config));
        new_token.append(getTokenEndTime(token_config));
        new_token.append(getTokenAcl(token_config));
        new_token.append(getTokenSessionID(token_config));
        new_token.append(getTokenPayload(token_config));

        StringBuilder hash_source = new StringBuilder(new_token);
        hash_source.append(getTokenUrl(token_config));
        hash_source.append(getTokenSalt(token_config));

        algo = getKeyValue(token_config, "algo", default_algo);
        String crypto_algo = "HmacSHA256";
        if (algo.equalsIgnoreCase("sha256"))
            crypto_algo = "HmacSHA256";
        else if (algo.equalsIgnoreCase("sha1"))
            crypto_algo = "HmacSHA1";
        else if (algo.equalsIgnoreCase("md5"))
            crypto_algo = "HmacMD5";

        try {
            Mac hmac = Mac.getInstance(crypto_algo);
            byte[] key_bytes = DatatypeConverter.parseHexBinary(getKeyValue(token_config, "key", ""));
            SecretKeySpec secret_key = new SecretKeySpec(key_bytes, crypto_algo);
            hmac.init(secret_key);
            byte[] hmac_bytes = hmac.doFinal(hash_source.substring(0, hash_source.length()-1).toString().getBytes());
            return getKeyValue(token_config, "token_name", default_token_name) + "=" +
                new_token.toString() + "hmac=" + String.format("%0" + (2*hmac.getMacLength()) +  "x",new BigInteger(1, hmac_bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new AkamaiTokenException(e.toString());
        } catch (InvalidKeyException e) {
            throw new AkamaiTokenException(e.toString());
        }
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) {
        Dictionary token_config = new Hashtable();
        if (args.length == 0) {
            displayHelp();
            System.exit(0);
        }
        for (int i=0 ; i < args.length ; i++) {
            String arg = args[i];
            String value;
            //System.out.println(arg);
            if ("-h".startsWith(arg) || "--help".startsWith(arg)) {
                displayHelp();
                System.exit(0);
            } else if ("--version".startsWith(arg)) {
                displayVersion();
                System.exit(0);
            } else if (arg.startsWith("-t") || arg.startsWith("--token_type")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("token_type", value);
            } else if (arg.startsWith("-n") || arg.startsWith("--token_name")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("token_name", value);
            } else if (arg.startsWith("-i") || arg.startsWith("--ip")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("ip_address", value);
            } else if (arg.startsWith("-s") || arg.startsWith("--start_time")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("start_time", value);
            } else if (arg.startsWith("-e") || arg.startsWith("--end_time")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("end_time", value);
            } else if (arg.startsWith("-w") || arg.startsWith("--window")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("window_seconds", value);
            } else if (arg.startsWith("-u") || arg.startsWith("--url")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("url", value);
            } else if (arg.startsWith("-a") || arg.startsWith("--acl")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("acl", value);
            } else if (arg.startsWith("-k") || arg.startsWith("--key")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("key", value);
            } else if (arg.startsWith("-p") || arg.startsWith("--payload")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("payload", value);
            } else if (arg.startsWith("-A") || arg.startsWith("--algo")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("algo", value);
            } else if (arg.startsWith("-S") || arg.startsWith("--salt")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("salt", value);
            } else if (arg.startsWith("-I") || arg.startsWith("--session_id")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("session_id", value);
            } else if (arg.startsWith("-d") || arg.startsWith("--field_delimiter")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("field_delimiter", value);
            } else if (arg.startsWith("-D") || arg.startsWith("--acl_delimiter")) {
                if (arg.contains("=")) {
                    value = arg.split("=")[1];
                } else {
                    i++;
                    value = args[i];
                }
                token_config.put("acl_delimiter", value);
            } else if (arg.startsWith("-x") || arg.startsWith("--escape_early")) {
                token_config.put("escape_early", new String("true"));
            } else if (arg.startsWith("-X") || arg.startsWith("--escape_early_upper")) {
                token_config.put("escape_early_upper", new String("true"));
            } else if (arg.startsWith("-v") || arg.startsWith("--verbose")) {
                token_config.put("verbose", new String("true"));
            }
        } // for
        try {
            System.out.println(generateToken(token_config));
        } catch (AkamaiTokenException e) {
            System.out.println(e);
        }
    }
}


