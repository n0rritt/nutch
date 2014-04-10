/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nutch.indexwriter.solr;

import java.io.IOException;
import java.net.MalformedURLException;

import org.apache.hadoop.mapred.JobConf;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.solr.client.solrj.impl.HttpSolrServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SolrUtils {

  public static Logger LOG = LoggerFactory.getLogger(SolrUtils.class);

  public static HttpSolrServer getHttpSolrServer(JobConf job) throws MalformedURLException {
    DefaultHttpClient client = new DefaultHttpClient();

    // Check for username/password
    if (job.getBoolean(SolrConstants.USE_AUTH, false)) {
      String username = job.get(SolrConstants.USERNAME);

      LOG.info("Authenticating as: " + username);

      AuthScope scope = new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT, AuthScope.ANY_REALM, AuthScope.ANY_SCHEME);

      client.getCredentialsProvider().setCredentials(scope, new UsernamePasswordCredentials(username, job.get(SolrConstants.PASSWORD)));

      BasicHttpContext context = new BasicHttpContext();
      BasicScheme basicAuth = new BasicScheme();
      context.setAttribute("preemptive-auth", basicAuth);

      client.addRequestInterceptor(new PreemptiveAuth(), 0);
    }

    String serverURL = job.get(SolrConstants.SERVER_URL);

    return new HttpSolrServer(serverURL, client);
  }

  public static String stripNonCharCodepoints(String input) {
    StringBuilder retval = new StringBuilder();
    char ch;

    for (int i = 0; i < input.length(); i++) {
      ch = input.charAt(i);

      // Strip all non-characters http://unicode.org/cldr/utility/list-unicodeset.jsp?a=[:Noncharacter_Code_Point=True:]
      // and non-printable control characters except tabulator, new line and carriage return
      if (ch % 0x10000 != 0xffff && // 0xffff - 0x10ffff range step 0x10000
          ch % 0x10000 != 0xfffe && // 0xfffe - 0x10fffe range
          (ch <= 0xfdd0 || ch >= 0xfdef) && // 0xfdd0 - 0xfdef
          (ch > 0x1F || ch == 0x9 || ch == 0xa || ch == 0xd)) {

        retval.append(ch);
      }
    }

    return retval.toString();
  }

  static class PreemptiveAuth implements HttpRequestInterceptor {

    public void process(
        final HttpRequest request,
        final HttpContext context) throws HttpException, IOException {
      AuthState authState = (AuthState) context.getAttribute(
          ClientContext.TARGET_AUTH_STATE);
      // If no auth scheme avaialble yet, try to initialize it preemptively
      if (authState.getAuthScheme() == null) {
        AuthScheme authScheme = (AuthScheme) context.getAttribute(
            "preemptive-auth");
        CredentialsProvider credsProvider = (CredentialsProvider) context.getAttribute(
            ClientContext.CREDS_PROVIDER);
        HttpHost targetHost = (HttpHost) context.getAttribute(
            ExecutionContext.HTTP_TARGET_HOST);
        if (authScheme != null) {
          Credentials creds = credsProvider.getCredentials(
              new AuthScope(
                  targetHost.getHostName(),
                  targetHost.getPort()));
          if (creds == null) {
            throw new HttpException("No credentials for preemptive authentication");
          }
          authState.setAuthScheme(authScheme);
          authState.setCredentials(creds);
        }
      }
    }
  }
}
