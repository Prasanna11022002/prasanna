# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ISessionHandlingAction
from java.io import PrintWriter
import json
import re

class BurpExtender(IBurpExtender, IHttpListener, ISessionHandlingAction):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)
        self._stderr    = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("SSO JSESSIONID JWT Auto Refresher")

        # Register BOTH listeners
        callbacks.registerHttpListener(self)
        callbacks.registerSessionHandlingAction(self)

        # =====================================================
        # CONFIGURE THESE VALUES ONLY
        # =====================================================

        self.sso_url = "https://sso.com/sgconnect/oauth2/authorize?scope=openid%20profile&response_type=code&redirect_uri=https://host.com/explorer-wa/&nonce=MTc4MDk4MTM1MTY50A%3D%3D&client_id=XXXXXXXXXXXXXXXX"

        self.sso_cookies = "SGX_tid=XXXXXXXXXXXXXXXXXXXXXXXX; sgx-11=XXXXXXXXXXXXXXXX; OAUTH_REQUEST_ATTRIBUTES=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; SGX_PRD_authN_sticky_id=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; amlbcookie=01; 12=XXXXXXXXXXXX"

        self.token_url = "https://host.com/explore-wa/token"

        # =====================================================

        self._jsessionid = None
        self._jwt_token  = None

        self._stdout.println("SSO JSESSIONID JWT Refresher loaded successfully")

    # ----------------------------------------------------------
    # IHttpListener - fires on Proxy, Logger, all passive tools
    # Detects expired JWT from response body
    # ----------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                return

            response_bytes = messageInfo.getResponse()
            if response_bytes is None:
                return

            resp_info   = self._helpers.analyzeResponse(response_bytes)
            body_offset = resp_info.getBodyOffset()
            resp_body   = self._helpers.bytesToString(response_bytes[body_offset:])

            if "Jwt token Expired!" not in resp_body:
                return

            self._stdout.println("IHttpListener - JWT expired detected - refreshing")
            self._do_full_refresh()

            if self._jwt_token:
                self._inject_jwt_into_request(messageInfo)

        except Exception as e:
            self._stderr.println("processHttpMessage error: " + str(e))

    # ----------------------------------------------------------
    # ISessionHandlingAction - fires on Repeater, Intruder,
    # Scanner, Extensions when Session Handling Rule is set
    # ----------------------------------------------------------
    def getActionName(self):
        return "SSO JSESSIONID JWT Auto Refresher"

    def performAction(self, currentRequest, macroItems):
        try:
            self._stdout.println("performAction triggered - checking JWT")

            # Always refresh token before sending request
            # from Repeater, Intruder, Scanner
            needs_refresh = False

            # Check if we have a token at all
            if not self._jwt_token:
                self._stdout.println("No JWT token found - refreshing")
                needs_refresh = True

            # Check current request - if it has an expired token, refresh
            if not needs_refresh:
                req_info = self._helpers.analyzeRequest(currentRequest.getRequest())
                for hdr in req_info.getHeaders():
                    if hdr.lower().startswith("authorization:"):
                        self._stdout.println("Authorization header found - will update with fresh token")
                        needs_refresh = True
                        break

            if needs_refresh:
                self._do_full_refresh()

            if self._jwt_token:
                self._inject_jwt_into_request(currentRequest)
                self._stdout.println("JWT injected via Session Handling Rule")

        except Exception as e:
            self._stderr.println("performAction error: " + str(e))

    # ----------------------------------------------------------
    # CORE REFRESH FLOW
    # ----------------------------------------------------------
    def _do_full_refresh(self):
        try:
            # Step 1 - SSO - get Location URL
            location_url = self._get_sso_location()
            if not location_url:
                self._stderr.println("FAILED Step 1 - could not get Location URL from SSO")
                return
            self._stdout.println("Step 1 done - Location URL obtained")

            # Step 2 - Follow Location URL - get JSESSIONID
            jsessionid = self._fetch_jsessionid(location_url)
            if not jsessionid:
                self._stderr.println("FAILED Step 2 - could not extract JSESSIONID")
                return
            self._jsessionid = jsessionid
            self._stdout.println("Step 2 done - JSESSIONID obtained")

            # Step 3 - Hit token endpoint - get JWT
            jwt_token = self._fetch_jwt()
            if not jwt_token:
                self._stderr.println("FAILED Step 3 - could not obtain JWT token")
                return
            self._jwt_token = jwt_token
            self._stdout.println("Step 3 done - JWT token obtained successfully")

        except Exception as e:
            self._stderr.println("_do_full_refresh error: " + str(e))

    # ----------------------------------------------------------
    # STEP 1 - GET SSO URL - extract Location header
    # ----------------------------------------------------------
    def _get_sso_location(self):
        try:
            host = self._host(self.sso_url)
            path = self._extract_path(self.sso_url)

            self._stdout.println("SSO path: " + path[:100])

            headers = [
                "GET " + path + " HTTP/1.1",
                "Host: " + host,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.9",
                "Accept-Encoding: gzip, deflate, br",
                "Referer: https://sso.com/",
                "Upgrade-Insecure-Requests: 1",
                "Sec-Fetch-Dest: document",
                "Sec-Fetch-Mode: navigate",
                "Sec-Fetch-Site: same-origin",
                "Sec-Fetch-User: ?1",
                "Priority: u=0, i",
                "Te: trailers",
                "Cookie: " + self.sso_cookies,
                "Connection: close"
            ]

            response_bytes = self._make_request(self.sso_url, headers, None)
            if response_bytes is None:
                self._stderr.println("SSO request returned no response")
                return None

            resp_info    = self._helpers.analyzeResponse(response_bytes)
            status       = resp_info.getStatusCode()
            resp_headers = resp_info.getHeaders()

            self._stdout.println("SSO response status: " + str(status))

            if status in [301, 302, 303, 307, 308]:
                for hdr in resp_headers:
                    if hdr.lower().startswith("location:"):
                        location = hdr.split(":", 1)[1].strip()
                        self._stdout.println("Location URL found: " + location[:80])
                        return location

            self._stderr.println("No Location header found. Status: " + str(status))
            return None

        except Exception as e:
            self._stderr.println("_get_sso_location error: " + str(e))
            return None

    # ----------------------------------------------------------
    # STEP 2 - Follow Location URL - extract JSESSIONID
    # ----------------------------------------------------------
    def _fetch_jsessionid(self, location_url):
        try:
            if location_url.startswith("/"):
                location_url = self._scheme(self.sso_url) + "://" + self._host(self.sso_url) + location_url

            host = self._host(location_url)
            path = self._extract_path(location_url)

            self._stdout.println("Following Location path: " + path[:100])

            headers = [
                "GET " + path + " HTTP/1.1",
                "Host: " + host,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.9",
                "Accept-Encoding: gzip, deflate, br",
                "Referer: https://sso.com/",
                "Sec-Fetch-Dest: document",
                "Sec-Fetch-Mode: navigate",
                "Sec-Fetch-Site: cross-site",
                "Cookie: " + self.sso_cookies,
                "Connection: close"
            ]

            response_bytes = self._make_request(location_url, headers, None)
            if response_bytes is None:
                self._stderr.println("Location URL request returned no response")
                return None

            resp_info    = self._helpers.analyzeResponse(response_bytes)
            status       = resp_info.getStatusCode()
            resp_headers = resp_info.getHeaders()

            self._stdout.println("Location URL response status: " + str(status))

            if status in [301, 302, 303, 307, 308]:
                self._stderr.println("302 on Location URL - SSO cookies expired - update sso_cookies manually")
                return None

            for hdr in resp_headers:
                if "set-cookie" in hdr.lower() and "jsessionid" in hdr.lower():
                    match = re.search(r'JSESSIONID=([^;,\s]+)', hdr, re.IGNORECASE)
                    if match:
                        self._stdout.println("JSESSIONID extracted successfully")
                        return match.group(1)

            self._stderr.println("JSESSIONID not found in Set-Cookie header")
            return None

        except Exception as e:
            self._stderr.println("_fetch_jsessionid error: " + str(e))
            return None

    # ----------------------------------------------------------
    # STEP 3 - GET token endpoint with JSESSIONID - extract JWT
    # ----------------------------------------------------------
    def _fetch_jwt(self):
        try:
            host = self._host(self.token_url)
            path = self._extract_path(self.token_url)

            headers = [
                "GET " + path + " HTTP/1.1",
                "Host: " + host,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
                "Accept: application/json, text/plain, */*",
                "Accept-Language: en-US,en;q=0.9",
                "Cookie: JSESSIONID=" + self._jsessionid,
                "Connection: close"
            ]

            response_bytes = self._make_request(self.token_url, headers, None)
            if response_bytes is None:
                self._stderr.println("Token endpoint returned no response")
                return None

            resp_info   = self._helpers.analyzeResponse(response_bytes)
            status      = resp_info.getStatusCode()
            body_offset = resp_info.getBodyOffset()
            resp_body   = self._helpers.bytesToString(response_bytes[body_offset:])

            self._stdout.println("Token endpoint status: " + str(status))

            if status in [301, 302, 303, 307, 308]:
                self._stderr.println("302 on token endpoint - JSESSIONID expired - restarting from SSO")
                location_url = self._get_sso_location()
                if not location_url:
                    return None
                jsessionid = self._fetch_jsessionid(location_url)
                if not jsessionid:
                    return None
                self._jsessionid = jsessionid
                return self._fetch_jwt()

            try:
                data  = json.loads(resp_body)
                token = data.get("token")
                if token:
                    self._stdout.println("JWT token extracted from response")
                    return token
                else:
                    self._stderr.println("Key token not found in response: " + resp_body[:200])
                    return None
            except Exception as e:
                self._stderr.println("JSON parse error: " + str(e) + " Body: " + resp_body[:200])
                return None

        except Exception as e:
            self._stderr.println("_fetch_jwt error: " + str(e))
            return None

    # ----------------------------------------------------------
    # INJECT JWT into any request object
    # ----------------------------------------------------------
    def _inject_jwt_into_request(self, requestResponse):
        try:
            original_request = requestResponse.getRequest()
            req_info         = self._helpers.analyzeRequest(original_request)
            headers          = list(req_info.getHeaders())
            body             = original_request[req_info.getBodyOffset():]

            new_headers = []
            replaced    = False

            for hdr in headers:
                if hdr.lower().startswith("authorization:"):
                    new_headers.append("Authorization: Bearer " + self._jwt_token)
                    replaced = True
                else:
                    new_headers.append(hdr)

            if not replaced:
                new_headers.append("Authorization: Bearer " + self._jwt_token)

            new_request = self._helpers.buildHttpMessage(new_headers, body)
            requestResponse.setRequest(new_request)
            self._stdout.println("JWT injected into request successfully")

        except Exception as e:
            self._stderr.println("_inject_jwt_into_request error: " + str(e))

    # ----------------------------------------------------------
    # UTILITY HELPERS
    # ----------------------------------------------------------
    def _make_request(self, url, headers, body):
        try:
            use_https  = url.lower().startswith("https")
            host       = self._host(url)
            port       = 443 if use_https else 80
            http_svc   = self._helpers.buildHttpService(host, port, use_https)
            body_bytes = self._helpers.stringToBytes(body) if body else []
            req_bytes  = self._helpers.buildHttpMessage(headers, body_bytes)
            response   = self._callbacks.makeHttpRequest(http_svc, req_bytes)
            return response.getResponse() if response else None
        except Exception as e:
            self._stderr.println("_make_request error: " + str(e))
            return None

    def _host(self, url):
        no_scheme = re.sub(r'^https?://', '', url)
        return no_scheme.split("/")[0].split("?")[0]

    def _scheme(self, url):
        return "https" if url.lower().startswith("https") else "http"

    def _extract_path(self, url):
        match = re.match(r'^https?://[^/]+(.*)', url)
        if match:
            path = match.group(1)
            return path if path else "/"
        return "/"
