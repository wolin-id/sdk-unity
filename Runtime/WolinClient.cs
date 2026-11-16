#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Wolin.Unity
{
    /// <summary>
    /// Asynchronous C# client for Wolin and W3C Solid 0.11 Pods supporting Solid-OIDC,
    /// RFC 9449 DPoP (<c>ES256</c>), WebID Profile &amp; <c>pim:storage</c> discovery,
    /// and Solid Linked Data Platform (LDP) CRUD with <c>ETag</c> concurrency control.
    /// </summary>
    public sealed class WolinClient : IDisposable
    {
        /// <summary>
        /// Official Wolin (月印千江) Solid-OIDC Provider &amp; Passport production endpoint.
        /// </summary>
        public const string DefaultAuthUrl = "https://auth.wolin.id";

        /// <summary>
        /// Official Wolin (月印千江) Sovereign Solid Pod Engine production endpoint.
        /// </summary>
        public const string DefaultPodUrl = "https://pod.wolin.id";

        /// <summary>
        /// Minimum allowed character length for a Wolin <c>pod_id</c> handle.
        /// </summary>
        public const int MinPodIdLength = 3;

        /// <summary>
        /// Maximum allowed character length for a Wolin <c>pod_id</c> handle.
        /// </summary>
        public const int MaxPodIdLength = 32;

        public const string DefaultRdfAccept =
            "text/turtle, application/ld+json;q=0.9, application/n-triples;q=0.8, text/n3;q=0.7";

        private const int MaxSafeRedirects = 5;

        private static readonly HashSet<string> ReservedPodIds = new HashSet<string>(StringComparer.Ordinal)
        {
            "abuse", "admin", "administrator", "ads", "api", "app", "apps", "assets",
            "auth", "authorize", "autoconfig", "autodiscover", "backup", "beta", "billing", "blog",
            "calendar", "cdn", "chat", "cloud", "consent", "console", "contact", "control",
            "corp", "dashboard", "data", "dev", "dns", "doc", "docs", "download",
            "downloads", "edge", "email", "engine", "enterprise", "entropy", "events", "files",
            "forum", "ftp", "gateway", "git", "graphql", "health", "healthz", "help",
            "home", "host", "hostmaster", "id", "idp", "images", "imap", "img",
            "inbox", "info", "internal", "jwks", "legal", "local", "localhost", "login",
            "logout", "logs", "mail", "mailer", "manage", "mcp", "media", "metrics",
            "mta-sts", "mx", "net", "news", "no-reply", "noreply", "notify", "ns",
            "ns1", "ns2", "ns3", "ns4", "oauth", "official", "oidc", "ops",
            "org", "origin", "passport", "pay", "payment", "payments", "pod", "pods",
            "pop", "pop3", "portal", "postmaster", "press", "pricing", "private", "prod",
            "production", "profile", "proxy", "pub", "public", "register", "registry", "relay",
            "root", "rpc", "rss", "sandbox", "search", "secure", "security", "server",
            "service", "services", "session", "settings", "sftp", "signin", "signout", "signup",
            "smtp", "solid", "sparql", "ssh", "sso", "stage", "staging", "static",
            "stats", "status", "storage", "store", "support", "sync", "sys", "system",
            "team", "telemetry", "terms", "test", "testing", "token", "trust", "updates",
            "upload", "uploads", "userinfo", "vault", "verify", "vpn", "wac", "web",
            "webhook", "webhooks", "webid", "webmail", "webmaster", "well-known", "wolin", "ws",
            "wss", "www"
        };

        private readonly HttpClient _httpClient;
        private readonly bool _disposeHttpClient;
        private readonly DPoPSigner _dpopSigner;
        private readonly bool _disposeSigner;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="WolinClient"/> class.
        /// </summary>
        /// <param name="httpClient">Optional <see cref="HttpClient"/> instance. If omitted, an internal client with <c>AllowAutoRedirect = false</c> is created.</param>
        /// <param name="dpopSigner">Optional <see cref="DPoPSigner"/> instance. If omitted, an ephemeral P-256 keypair is generated.</param>
        /// <param name="disposeHttpClient">Whether disposing <see cref="WolinClient"/> should dispose a caller-supplied <paramref name="httpClient"/>.</param>
        /// <param name="disposeSigner">Whether disposing <see cref="WolinClient"/> should dispose a caller-supplied <paramref name="dpopSigner"/>.</param>
        public WolinClient(
            HttpClient? httpClient = null,
            DPoPSigner? dpopSigner = null,
            bool disposeHttpClient = false,
            bool disposeSigner = false)
        {
            if (httpClient == null)
            {
                var handler = new HttpClientHandler
                {
                    AllowAutoRedirect = false
                };
                _httpClient = new HttpClient(handler, disposeHandler: true);
                _disposeHttpClient = true;
            }
            else
            {
                _httpClient = httpClient;
                _disposeHttpClient = disposeHttpClient;
            }

            if (dpopSigner == null)
            {
                _dpopSigner = new DPoPSigner();
                _disposeSigner = true;
            }
            else
            {
                _dpopSigner = dpopSigner;
                _disposeSigner = disposeSigner;
            }
        }

        /// <summary>
        /// Gets the active RFC 9449 <see cref="DPoPSigner"/> bound to this client session.
        /// </summary>
        public DPoPSigner DPoPSigner => _dpopSigner;

        /// <summary>
        /// Gets the currently configured DPoP-bound Solid-OIDC access token, if authenticated.
        /// </summary>
        public string? AccessToken { get; private set; }

        /// <summary>
        /// Gets the authenticated agent's WebID URI, if known.
        /// </summary>
        public string? WebId { get; private set; }

        /// <summary>
        /// Gets or sets the latest RFC 9449 <c>DPoP-Nonce</c> issued by the server.
        /// Automatically updated whenever a response includes a <c>DPoP-Nonce</c> header.
        /// </summary>
        public string? DPoPNonce { get; set; }

        /// <summary>
        /// Validates a Wolin <c>pod_id</c> handle (<c>3..32</c> chars, lowercase ASCII <c>[a-z0-9-]</c>,
        /// starts and ends with <c>[a-z0-9]</c>, no consecutive <c>--</c>, and not a reserved infrastructure handle).
        /// Throws <see cref="WolinException"/> when invalid.
        /// </summary>
        public static string ValidatePodId(string podId)
        {
            if (podId == null)
            {
                throw new WolinException("pod_id must not be null.");
            }

            if (podId.Length < MinPodIdLength || podId.Length > MaxPodIdLength)
            {
                throw new WolinException(
                    $"pod_id must be between {MinPodIdLength} and {MaxPodIdLength} lowercase characters.");
            }

            if (podId[0] == '-' || podId[podId.Length - 1] == '-')
            {
                throw new WolinException(
                    "pod_id must contain only lowercase ASCII [a-z0-9-] and start and end with [a-z0-9].");
            }

            for (int i = 0; i < podId.Length; i++)
            {
                char c = podId[i];
                bool isLower = c >= 'a' && c <= 'z';
                bool isDigit = c >= '0' && c <= '9';
                if (!isLower && !isDigit && c != '-')
                {
                    throw new WolinException(
                        "pod_id must contain only lowercase ASCII [a-z0-9-] and start and end with [a-z0-9].");
                }
            }

            if (podId.IndexOf("--", StringComparison.Ordinal) >= 0)
            {
                throw new WolinException("pod_id must not contain consecutive hyphens ('--').");
            }

            if (ReservedPodIds.Contains(podId))
            {
                throw new WolinException($"pod_id '{podId}' is reserved for system infrastructure.");
            }

            return podId;
        }

        /// <summary>
        /// Returns <c>true</c> if <paramref name="podId"/> satisfies all Wolin <c>pod_id</c> syntax and reservation rules.
        /// </summary>
        public static bool IsValidPodId(string? podId)
        {
            if (string.IsNullOrEmpty(podId))
            {
                return false;
            }

            try
            {
                _ = ValidatePodId(podId!);
                return true;
            }
            catch (WolinException)
            {
                return false;
            }
        }

        /// <summary>
        /// Configures the DPoP-bound Solid-OIDC access token (and optional WebID) used to authenticate subsequent LDP requests.
        /// </summary>
        public void SetAccessToken(string? accessToken, string? webId = null)
        {
            ThrowIfDisposed();
            AccessToken = string.IsNullOrWhiteSpace(accessToken) ? null : accessToken!.Trim();
            if (webId != null)
            {
                WebId = string.IsNullOrWhiteSpace(webId) ? null : webId.Trim();
            }
        }

        /// <summary>
        /// Clears any active Solid-OIDC access token, WebID, and cached DPoP nonce.
        /// </summary>
        public void ClearCredentials()
        {
            ThrowIfDisposed();
            AccessToken = null;
            WebId = null;
            DPoPNonce = null;
        }

        /// <summary>
        /// Exchanges an OAuth 2.0 / Solid-OIDC authorization code + PKCE verifier at <paramref name="tokenEndpoint"/>
        /// using an RFC 9449 DPoP proof, stores the returned access token on this client, and returns the token response.
        /// </summary>
        public async Task<SolidOidcTokenResponse> ExchangeAuthorizationCodeAsync(
            Uri tokenEndpoint,
            string clientId,
            string code,
            string redirectUri,
            string codeVerifier,
            string? clientSecret = null,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (tokenEndpoint == null)
            {
                throw new ArgumentNullException(nameof(tokenEndpoint));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentException("Client ID must not be empty.", nameof(clientId));
            }

            if (string.IsNullOrWhiteSpace(code))
            {
                throw new ArgumentException("Authorization code must not be empty.", nameof(code));
            }

            if (string.IsNullOrWhiteSpace(redirectUri))
            {
                throw new ArgumentException("Redirect URI must not be empty.", nameof(redirectUri));
            }

            if (string.IsNullOrWhiteSpace(codeVerifier))
            {
                throw new ArgumentException("PKCE code_verifier must not be empty.", nameof(codeVerifier));
            }

            var formFields = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("code_verifier", codeVerifier)
            };

            if (!string.IsNullOrEmpty(clientSecret))
            {
                formFields.Add(new KeyValuePair<string, string>("client_secret", clientSecret!));
            }

            return await SendTokenRequestAsync(tokenEndpoint, formFields, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Dereferences a W3C Solid WebID URI and parses its Turtle profile document (<c>pim:storage</c>, <c>solid:oidcIssuer</c>, <c>ldp:inbox</c>).
        /// </summary>
        public async Task<WebIdProfile> FetchWebIdProfileAsync(
            string webId,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            Uri profileDocUri = WebIdParser.GetProfileDocumentUri(webId);
            PodResource response = await GetAsync(
                profileDocUri,
                ifNoneMatch: null,
                accept: "text/turtle, text/n3;q=0.9",
                cancellationToken: cancellationToken).ConfigureAwait(false);

            string turtle = response.ContentAsUtf8();
            return WebIdParser.ParseTurtle(turtle, webId, profileDocUri.AbsoluteUri);
        }

        /// <summary>
        /// Dereferences <paramref name="webId"/> and discovers its primary <c>pim:storage</c> Solid Pod root URI.
        /// Throws <see cref="WolinException"/> if no <c>pim:storage</c> triple is declared for the WebID.
        /// </summary>
        public async Task<Uri> DiscoverStorageAsync(
            string webId,
            CancellationToken cancellationToken = default)
        {
            WebIdProfile profile = await FetchWebIdProfileAsync(webId, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(profile.PrimaryStorage))
            {
                throw new WolinException(
                    $"WebID Profile '{webId}' does not declare a pim:storage (<{WebIdParser.PimStorageIri}>) triple.");
            }

            if (!Uri.TryCreate(profile.PrimaryStorage, UriKind.Absolute, out Uri? storageUri))
            {
                throw new WolinException(
                    $"WebID Profile '{webId}' declared a malformed pim:storage URI '{profile.PrimaryStorage}'.");
            }

            return storageUri;
        }

        /// <summary>
        /// Performs a Solid LDP <c>GET</c> request against <paramref name="resourceUrl"/>, returning a <see cref="PodResource"/> with payload and <c>ETag</c>.
        /// If <paramref name="ifNoneMatch"/> is supplied and matches on the server, returns a <see cref="PodResource"/> with <see cref="HttpStatusCode.NotModified"/>.
        /// </summary>
        public Task<PodResource> GetAsync(
            string resourceUrl,
            string? ifNoneMatch = null,
            string? accept = null,
            CancellationToken cancellationToken = default)
        {
            return GetAsync(ParseResourceUri(resourceUrl), ifNoneMatch, accept, cancellationToken);
        }

        /// <summary>
        /// Performs a Solid LDP <c>GET</c> request against <paramref name="resourceUri"/>, returning a <see cref="PodResource"/> with payload and <c>ETag</c>.
        /// If <paramref name="ifNoneMatch"/> is supplied and matches on the server, returns a <see cref="PodResource"/> with <see cref="HttpStatusCode.NotModified"/>.
        /// </summary>
        public async Task<PodResource> GetAsync(
            Uri resourceUri,
            string? ifNoneMatch = null,
            string? accept = null,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (resourceUri == null)
            {
                throw new ArgumentNullException(nameof(resourceUri));
            }

            string acceptHeader = string.IsNullOrWhiteSpace(accept) ? DefaultRdfAccept : accept!;
            ValidateHeaderValue(acceptHeader, nameof(accept));

            Func<HttpRequestMessage> factory = () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, resourceUri);
                req.Headers.TryAddWithoutValidation("Accept", acceptHeader);

                if (!string.IsNullOrWhiteSpace(ifNoneMatch))
                {
                    req.Headers.TryAddWithoutValidation("If-None-Match", FormatEntityTag(ifNoneMatch!));
                }

                return req;
            };

            HttpResponseMessage response = await SendWithDpopAsync(factory, attachAccessToken: true, cancellationToken).ConfigureAwait(false);
            string? fallbackETag = null;
            IReadOnlyDictionary<string, IReadOnlyList<string>>? fallbackHeaders = null;

            try
            {
                if (IsRedirectStatusCode(response.StatusCode))
                {
                    fallbackETag = ExtractETag(response);
                    fallbackHeaders = CollectHeaders(response);
                    Uri currentUri = resourceUri;

                    for (int hop = 0; hop < MaxSafeRedirects; hop++)
                    {
                        Uri? nextUri = ResolveRedirectLocation(currentUri, response);
                        if (nextUri == null)
                        {
                            break;
                        }

                        bool sameOrigin = IsSameOrigin(resourceUri, nextUri);
                        response.Dispose();

                        Uri targetHopUri = nextUri;
                        Func<HttpRequestMessage> redirectFactory = () =>
                        {
                            var redirectReq = new HttpRequestMessage(HttpMethod.Get, targetHopUri);
                            redirectReq.Headers.TryAddWithoutValidation("Accept", acceptHeader);
                            return redirectReq;
                        };

                        response = await SendWithDpopAsync(
                            redirectFactory,
                            attachAccessToken: sameOrigin,
                            cancellationToken).ConfigureAwait(false);
                        currentUri = nextUri;

                        if (!IsRedirectStatusCode(response.StatusCode))
                        {
                            break;
                        }

                        if (hop == MaxSafeRedirects - 1)
                        {
                            throw new WolinException(
                                $"Exceeded maximum redirect hops ({MaxSafeRedirects}) while fetching '{resourceUri}'.");
                        }
                    }
                }

                if (response.StatusCode == HttpStatusCode.NotModified && !string.IsNullOrWhiteSpace(ifNoneMatch))
                {
                    return await ToPodResourceAsync(resourceUri, response, readBody: false, fallbackETag, fallbackHeaders).ConfigureAwait(false);
                }

                await EnsureSuccessOrThrowAsync(resourceUri, response).ConfigureAwait(false);
                return await ToPodResourceAsync(resourceUri, response, readBody: true, fallbackETag, fallbackHeaders).ConfigureAwait(false);
            }
            finally
            {
                response.Dispose();
            }
        }

        /// <summary>
        /// Performs a Solid LDP <c>PUT</c> request with a UTF-8 string body (defaults to <c>text/turtle</c>) and optional <c>ETag</c> concurrency preconditions.
        /// </summary>
        public Task<PodResource> PutAsync(
            string resourceUrl,
            string content,
            string contentType = "text/turtle",
            string? ifMatch = null,
            bool createOnly = false,
            CancellationToken cancellationToken = default)
        {
            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }

            return PutAsync(
                ParseResourceUri(resourceUrl),
                Encoding.UTF8.GetBytes(content),
                contentType,
                ifMatch,
                createOnly,
                cancellationToken);
        }

        /// <summary>
        /// Performs a Solid LDP <c>PUT</c> request with a UTF-8 string body (defaults to <c>text/turtle</c>) and optional <c>ETag</c> concurrency preconditions.
        /// </summary>
        public Task<PodResource> PutAsync(
            Uri resourceUri,
            string content,
            string contentType = "text/turtle",
            string? ifMatch = null,
            bool createOnly = false,
            CancellationToken cancellationToken = default)
        {
            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }

            return PutAsync(
                resourceUri,
                Encoding.UTF8.GetBytes(content),
                contentType,
                ifMatch,
                createOnly,
                cancellationToken);
        }

        /// <summary>
        /// Performs a Solid LDP <c>PUT</c> request with binary payload and optional <c>If-Match</c> / <c>If-None-Match: *</c> concurrency control.
        /// </summary>
        public Task<PodResource> PutAsync(
            string resourceUrl,
            byte[] content,
            string contentType = "application/octet-stream",
            string? ifMatch = null,
            bool createOnly = false,
            CancellationToken cancellationToken = default)
        {
            return PutAsync(ParseResourceUri(resourceUrl), content, contentType, ifMatch, createOnly, cancellationToken);
        }

        /// <summary>
        /// Performs a Solid LDP <c>PUT</c> request with binary payload and optional <c>If-Match</c> / <c>If-None-Match: *</c> concurrency control.
        /// </summary>
        /// <param name="resourceUri">Target Solid Pod resource URI.</param>
        /// <param name="content">Payload bytes to write.</param>
        /// <param name="contentType">MIME media type (e.g., <c>text/turtle</c> or <c>application/octet-stream</c>).</param>
        /// <param name="ifMatch">Optional <c>ETag</c> precondition for optimistic concurrency (<c>If-Match</c>).</param>
        /// <param name="createOnly">If <c>true</c>, sends <c>If-None-Match: *</c> so the write fails with <c>412 Precondition Failed</c> if the resource already exists.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        public async Task<PodResource> PutAsync(
            Uri resourceUri,
            byte[] content,
            string contentType = "application/octet-stream",
            string? ifMatch = null,
            bool createOnly = false,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (resourceUri == null)
            {
                throw new ArgumentNullException(nameof(resourceUri));
            }

            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }

            if (string.IsNullOrWhiteSpace(contentType))
            {
                throw new ArgumentException("Content-Type must not be empty.", nameof(contentType));
            }

            if (!string.IsNullOrWhiteSpace(ifMatch) && createOnly)
            {
                throw new ArgumentException("Cannot specify both 'ifMatch' and 'createOnly' preconditions on PUT.");
            }

            Func<HttpRequestMessage> factory = () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Put, resourceUri);
                var byteContent = new ByteArrayContent(content);
                byteContent.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
                req.Content = byteContent;

                if (!string.IsNullOrWhiteSpace(ifMatch))
                {
                    req.Headers.TryAddWithoutValidation("If-Match", FormatEntityTag(ifMatch!));
                }
                else if (createOnly)
                {
                    req.Headers.TryAddWithoutValidation("If-None-Match", "*");
                }

                return req;
            };

            using (HttpResponseMessage response = await SendWithDpopAsync(factory, attachAccessToken: true, cancellationToken).ConfigureAwait(false))
            {
                await EnsureSuccessOrThrowAsync(resourceUri, response).ConfigureAwait(false);
                PodResource result = await ToPodResourceAsync(resourceUri, response, readBody: true).ConfigureAwait(false);
                if (result.Content.Length == 0 && response.Content?.Headers?.ContentType == null)
                {
                    return new PodResource(resourceUri, result.Content, contentType, result.ETag, result.StatusCode, result.Headers);
                }

                return result;
            }
        }

        /// <summary>
        /// Performs a Solid LDP <c>DELETE</c> request against <paramref name="resourceUrl"/> with optional <c>If-Match</c> <c>ETag</c> precondition.
        /// </summary>
        public Task DeleteAsync(
            string resourceUrl,
            string? ifMatch = null,
            CancellationToken cancellationToken = default)
        {
            return DeleteAsync(ParseResourceUri(resourceUrl), ifMatch, cancellationToken);
        }

        /// <summary>
        /// Performs a Solid LDP <c>DELETE</c> request against <paramref name="resourceUri"/> with optional <c>If-Match</c> <c>ETag</c> precondition.
        /// </summary>
        public async Task DeleteAsync(
            Uri resourceUri,
            string? ifMatch = null,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (resourceUri == null)
            {
                throw new ArgumentNullException(nameof(resourceUri));
            }

            Func<HttpRequestMessage> factory = () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Delete, resourceUri);
                if (!string.IsNullOrWhiteSpace(ifMatch))
                {
                    req.Headers.TryAddWithoutValidation("If-Match", FormatEntityTag(ifMatch!));
                }

                return req;
            };

            using (HttpResponseMessage response = await SendWithDpopAsync(factory, attachAccessToken: true, cancellationToken).ConfigureAwait(false))
            {
                await EnsureSuccessOrThrowAsync(resourceUri, response).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Releases managed resources owned by this <see cref="WolinClient"/>.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_disposeHttpClient)
            {
                _httpClient.Dispose();
            }

            if (_disposeSigner)
            {
                _dpopSigner.Dispose();
            }
        }

        private async Task<SolidOidcTokenResponse> SendTokenRequestAsync(
            Uri tokenEndpoint,
            IReadOnlyList<KeyValuePair<string, string>> formFields,
            CancellationToken cancellationToken)
        {
            Func<HttpRequestMessage> factory = () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
                {
                    Content = new FormUrlEncodedContent(formFields)
                };
                req.Headers.TryAddWithoutValidation("Accept", "application/json");
                return req;
            };

            // Token endpoint requests use a DPoP proof WITHOUT an 'ath' access token hash (RFC 9449 §5).
            using (HttpResponseMessage response = await SendWithDpopAsync(
                factory,
                attachAccessToken: false,
                cancellationToken,
                alwaysAttachDpopProof: true).ConfigureAwait(false))
            {
                await EnsureSuccessOrThrowAsync(tokenEndpoint, response).ConfigureAwait(false);
                string body = response.Content == null
                    ? string.Empty
                    : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                Dictionary<string, string?> fields = MinimalJsonObjectParser.ParseFlatObject(body);
                if (!fields.TryGetValue("access_token", out string? accessToken) || string.IsNullOrWhiteSpace(accessToken))
                {
                    throw new WolinException("Solid-OIDC token endpoint response did not include an 'access_token'.");
                }

                fields.TryGetValue("token_type", out string? tokenType);
                fields.TryGetValue("id_token", out string? idToken);
                fields.TryGetValue("refresh_token", out string? refreshToken);
                fields.TryGetValue("scope", out string? scope);

                int? expiresIn = null;
                if (fields.TryGetValue("expires_in", out string? rawExp)
                    && int.TryParse(rawExp, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedExp))
                {
                    expiresIn = parsedExp;
                }

                AccessToken = accessToken;
                return new SolidOidcTokenResponse(
                    accessToken!,
                    tokenType ?? "DPoP",
                    idToken,
                    refreshToken,
                    expiresIn,
                    scope);
            }
        }

        private async Task<HttpResponseMessage> SendWithDpopAsync(
            Func<HttpRequestMessage> requestFactory,
            bool attachAccessToken,
            CancellationToken cancellationToken,
            bool alwaysAttachDpopProof = false)
        {
            string? token = attachAccessToken ? AccessToken : null;
            bool useDpop = alwaysAttachDpopProof || !string.IsNullOrEmpty(token);
            string? nonceUsed = DPoPNonce;

            HttpResponseMessage response = await SendSingleAttemptAsync(
                requestFactory,
                token,
                useDpop,
                nonceUsed,
                cancellationToken).ConfigureAwait(false);

            string? serverNonce = ExtractHeaderFirst(response.Headers, "DPoP-Nonce");
            if (!string.IsNullOrWhiteSpace(serverNonce))
            {
                DPoPNonce = serverNonce;
            }

            // RFC 9449 §8 / §9: If the resource server or authorization server challenges with a new DPoP-Nonce
            // on 401 Unauthorized (LDP resource) or 400 Bad Request (token endpoint), retry once with a fresh proof.
            if (useDpop
                && !string.IsNullOrWhiteSpace(serverNonce)
                && !string.Equals(serverNonce, nonceUsed, StringComparison.Ordinal)
                && (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.BadRequest))
            {
                response.Dispose();
                response = await SendSingleAttemptAsync(
                    requestFactory,
                    token,
                    useDpop: true,
                    nonce: serverNonce,
                    cancellationToken).ConfigureAwait(false);

                string? nextNonce = ExtractHeaderFirst(response.Headers, "DPoP-Nonce");
                if (!string.IsNullOrWhiteSpace(nextNonce))
                {
                    DPoPNonce = nextNonce;
                }
            }

            return response;
        }

        private async Task<HttpResponseMessage> SendSingleAttemptAsync(
            Func<HttpRequestMessage> requestFactory,
            string? accessToken,
            bool useDpop,
            string? nonce,
            CancellationToken cancellationToken)
        {
            using (HttpRequestMessage request = requestFactory())
            {
                if (request.RequestUri == null)
                {
                    throw new WolinException("HTTP request is missing a target RequestUri.");
                }

                if (!string.IsNullOrEmpty(accessToken))
                {
                    ValidateHeaderValue(accessToken!, nameof(AccessToken));
                    request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
                }

                if (useDpop)
                {
                    string proof = _dpopSigner.CreateProof(
                        request.Method.Method,
                        request.RequestUri,
                        accessToken,
                        nonce);
                    request.Headers.TryAddWithoutValidation("DPoP", proof);
                }

                return await _httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseContentRead,
                    cancellationToken).ConfigureAwait(false);
            }
        }

        private static async Task<PodResource> ToPodResourceAsync(
            Uri requestUri,
            HttpResponseMessage response,
            bool readBody,
            string? fallbackETag = null,
            IReadOnlyDictionary<string, IReadOnlyList<string>>? fallbackHeaders = null)
        {
            byte[] payload = readBody && response.Content != null
                ? await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false)
                : Array.Empty<byte>();

            string? contentType = response.Content?.Headers?.ContentType?.ToString();
            string? eTag = ExtractETag(response) ?? fallbackETag;
            IReadOnlyDictionary<string, IReadOnlyList<string>> headers = CollectHeaders(response, fallbackHeaders);

            return new PodResource(
                requestUri,
                payload,
                contentType,
                eTag,
                response.StatusCode,
                headers);
        }

        private static bool IsRedirectStatusCode(HttpStatusCode statusCode)
        {
            int code = (int)statusCode;
            return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
        }

        private static Uri? ResolveRedirectLocation(Uri baseUri, HttpResponseMessage response)
        {
            Uri? locationUri = response.Headers.Location;
            if (locationUri == null)
            {
                string? rawLoc = ExtractHeaderFirst(response.Headers, "Location");
                if (string.IsNullOrWhiteSpace(rawLoc))
                {
                    return null;
                }

                if (!Uri.TryCreate(rawLoc, UriKind.RelativeOrAbsolute, out Uri? parsedLoc) || parsedLoc == null)
                {
                    throw new WolinException($"Malformed redirect Location header '{rawLoc}'.");
                }

                locationUri = parsedLoc;
            }

            Uri resolved = locationUri.IsAbsoluteUri ? locationUri : new Uri(baseUri, locationUri);
            if ((resolved.Scheme != Uri.UriSchemeHttp && resolved.Scheme != Uri.UriSchemeHttps)
                || !string.IsNullOrEmpty(resolved.UserInfo))
            {
                throw new WolinException($"Disallowed redirect Location target '{resolved}'.");
            }

            return resolved;
        }

        private static bool IsSameOrigin(Uri first, Uri second)
        {
            return string.Equals(first.Scheme, second.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(first.Host, second.Host, StringComparison.OrdinalIgnoreCase)
                && first.Port == second.Port;
        }

        private static async Task EnsureSuccessOrThrowAsync(Uri requestUri, HttpResponseMessage response)
        {
            if (response.IsSuccessStatusCode)
            {
                return;
            }

            string? responseBody = null;
            if (response.Content != null)
            {
                try
                {
                    responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                }
                catch
                {
                    responseBody = null;
                }
            }

            string? dpopNonce = ExtractHeaderFirst(response.Headers, "DPoP-Nonce");
            int code = (int)response.StatusCode;
            string detail = string.IsNullOrWhiteSpace(responseBody)
                ? response.ReasonPhrase ?? response.StatusCode.ToString()
                : responseBody!.Trim();

            throw new WolinHttpException(
                $"Solid request to '{requestUri}' failed with HTTP {code} ({response.StatusCode}): {detail}",
                response.StatusCode,
                requestUri,
                responseBody,
                dpopNonce);
        }

        private static string? ExtractETag(HttpResponseMessage response)
        {
            if (response.Headers.ETag != null)
            {
                return response.Headers.ETag.ToString();
            }

            return ExtractHeaderFirst(response.Headers, "ETag");
        }

        private static string? ExtractHeaderFirst(HttpHeaders headers, string name)
        {
            if (headers.TryGetValues(name, out IEnumerable<string>? values))
            {
                foreach (string val in values)
                {
                    if (!string.IsNullOrWhiteSpace(val))
                    {
                        return val.Trim();
                    }
                }
            }

            return null;
        }

        private static IReadOnlyDictionary<string, IReadOnlyList<string>> CollectHeaders(
            HttpResponseMessage response,
            IReadOnlyDictionary<string, IReadOnlyList<string>>? fallbackHeaders = null)
        {
            var dict = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (KeyValuePair<string, IEnumerable<string>> kvp in response.Headers)
            {
                dict[kvp.Key] = ToReadOnlyList(kvp.Value);
            }

            if (response.Content != null)
            {
                foreach (KeyValuePair<string, IEnumerable<string>> kvp in response.Content.Headers)
                {
                    if (dict.TryGetValue(kvp.Key, out IReadOnlyList<string>? existing))
                    {
                        var merged = new List<string>(existing.Count + 2);
                        merged.AddRange(existing);
                        merged.AddRange(kvp.Value);
                        dict[kvp.Key] = new ReadOnlyCollection<string>(merged);
                    }
                    else
                    {
                        dict[kvp.Key] = ToReadOnlyList(kvp.Value);
                    }
                }
            }

            if (fallbackHeaders != null)
            {
                string[] fallbackKeys = { "Link", "WAC-Allow", "ETag" };
                for (int i = 0; i < fallbackKeys.Length; i++)
                {
                    string key = fallbackKeys[i];
                    if (!dict.ContainsKey(key) && fallbackHeaders.TryGetValue(key, out IReadOnlyList<string>? fallbackVals))
                    {
                        dict[key] = fallbackVals;
                    }
                }
            }

            return new ReadOnlyDictionary<string, IReadOnlyList<string>>(dict);
        }

        private static IReadOnlyList<string> ToReadOnlyList(IEnumerable<string> items)
        {
            var list = new List<string>();
            foreach (string item in items)
            {
                list.Add(item);
            }

            return new ReadOnlyCollection<string>(list);
        }

        internal static string FormatEntityTag(string rawETag)
        {
            ValidateHeaderValue(rawETag, nameof(rawETag));
            string trimmed = rawETag.Trim();
            if (trimmed.Length == 0)
            {
                throw new ArgumentException("ETag value must not be empty.", nameof(rawETag));
            }

            if (trimmed == "*")
            {
                return "*";
            }

            if (trimmed.StartsWith("W/\"", StringComparison.Ordinal) && trimmed.EndsWith("\"", StringComparison.Ordinal) && trimmed.Length >= 4)
            {
                return trimmed;
            }

            if (trimmed.StartsWith("\"", StringComparison.Ordinal) && trimmed.EndsWith("\"", StringComparison.Ordinal) && trimmed.Length >= 2)
            {
                return trimmed;
            }

            return string.Concat("\"", trimmed, "\"");
        }

        private static Uri ParseResourceUri(string resourceUrl)
        {
            if (string.IsNullOrWhiteSpace(resourceUrl))
            {
                throw new ArgumentException("Solid resource URL must not be empty.", nameof(resourceUrl));
            }

            if (!Uri.TryCreate(resourceUrl, UriKind.Absolute, out Uri? uri)
                || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                throw new ArgumentException($"Invalid absolute HTTP(S) Solid resource URL '{resourceUrl}'.", nameof(resourceUrl));
            }

            return uri;
        }

        private static void ValidateHeaderValue(string value, string paramName)
        {
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (c == '\r' || c == '\n' || c == '\0')
                {
                    throw new ArgumentException("HTTP header value must not contain CR, LF, or NUL control characters.", paramName);
                }
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(WolinClient));
            }
        }

        /// <summary>
        /// Zero-dependency RFC 8259 JSON flat object reader for OIDC token endpoint responses.
        /// </summary>
        internal static class MinimalJsonObjectParser
        {
            public static Dictionary<string, string?> ParseFlatObject(string json)
            {
                if (string.IsNullOrWhiteSpace(json))
                {
                    throw new WolinException("Expected JSON object payload, but response body was empty.");
                }

                int pos = 0;
                SkipWs(json, ref pos);
                if (pos >= json.Length || json[pos] != '{')
                {
                    throw new WolinException("Malformed JSON payload: expected '{'.");
                }

                pos++;
                var result = new Dictionary<string, string?>(StringComparer.Ordinal);
                SkipWs(json, ref pos);
                if (pos < json.Length && json[pos] == '}')
                {
                    return result;
                }

                while (pos < json.Length)
                {
                    SkipWs(json, ref pos);
                    string key = ReadJsonString(json, ref pos);
                    SkipWs(json, ref pos);
                    if (pos >= json.Length || json[pos] != ':')
                    {
                        throw new WolinException("Malformed JSON payload: expected ':'.");
                    }

                    pos++;
                    SkipWs(json, ref pos);
                    string? val = ReadJsonValueAsString(json, ref pos);
                    result[key] = val;

                    SkipWs(json, ref pos);
                    if (pos < json.Length && json[pos] == ',')
                    {
                        pos++;
                        continue;
                    }

                    if (pos < json.Length && json[pos] == '}')
                    {
                        pos++;
                        return result;
                    }

                    throw new WolinException("Malformed JSON payload: expected ',' or '}'.");
                }

                throw new WolinException("Unterminated JSON object.");
            }

            private static string? ReadJsonValueAsString(string json, ref int pos)
            {
                if (pos >= json.Length)
                {
                    throw new WolinException("Unexpected end of JSON value.");
                }

                char c = json[pos];
                if (c == '"')
                {
                    return ReadJsonString(json, ref pos);
                }

                if (c == '{' || c == '[')
                {
                    int start = pos;
                    SkipComposite(json, ref pos);
                    return json.Substring(start, pos - start);
                }

                int tokenStart = pos;
                while (pos < json.Length && !char.IsWhiteSpace(json[pos]) && json[pos] != ',' && json[pos] != '}' && json[pos] != ']')
                {
                    pos++;
                }

                string raw = json.Substring(tokenStart, pos - tokenStart);
                return string.Equals(raw, "null", StringComparison.Ordinal) ? null : raw;
            }

            private static void SkipComposite(string json, ref int pos)
            {
                int depth = 0;
                while (pos < json.Length)
                {
                    char c = json[pos];
                    if (c == '"')
                    {
                        _ = ReadJsonString(json, ref pos);
                        continue;
                    }

                    if (c == '{' || c == '[')
                    {
                        depth++;
                    }
                    else if (c == '}' || c == ']')
                    {
                        depth--;
                        if (depth == 0)
                        {
                            pos++;
                            return;
                        }
                    }

                    pos++;
                }

                throw new WolinException("Unterminated nested JSON structure.");
            }

            private static string ReadJsonString(string json, ref int pos)
            {
                if (pos >= json.Length || json[pos] != '"')
                {
                    throw new WolinException("Expected JSON string.");
                }

                pos++;
                var sb = new StringBuilder();
                while (pos < json.Length)
                {
                    char c = json[pos++];
                    if (c == '"')
                    {
                        return sb.ToString();
                    }

                    if (c == '\\')
                    {
                        if (pos >= json.Length)
                        {
                            throw new WolinException("Unterminated escape in JSON string.");
                        }

                        char esc = json[pos++];
                        switch (esc)
                        {
                            case '"': sb.Append('"'); break;
                            case '\\': sb.Append('\\'); break;
                            case '/': sb.Append('/'); break;
                            case 'b': sb.Append('\b'); break;
                            case 'f': sb.Append('\f'); break;
                            case 'n': sb.Append('\n'); break;
                            case 'r': sb.Append('\r'); break;
                            case 't': sb.Append('\t'); break;
                            case 'u':
                                if (pos + 4 > json.Length)
                                {
                                    throw new WolinException("Truncated '\\u' escape in JSON string.");
                                }

                                string hex = json.Substring(pos, 4);
                                pos += 4;
                                if (!int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int cp))
                                {
                                    throw new WolinException("Invalid '\\u' hex escape in JSON string.");
                                }

                                sb.Append((char)cp);
                                break;
                            default:
                                throw new WolinException($"Invalid JSON escape '\\{esc}'.");
                        }
                    }
                    else
                    {
                        sb.Append(c);
                    }
                }

                throw new WolinException("Unterminated JSON string.");
            }

            private static void SkipWs(string json, ref int pos)
            {
                while (pos < json.Length && char.IsWhiteSpace(json[pos]))
                {
                    pos++;
                }
            }
        }
    }
}
