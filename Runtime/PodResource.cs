#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Net;
using System.Text;

namespace Wolin.Unity
{
    /// <summary>
    /// Represents a W3C Solid Linked Data Platform (LDP) resource retrieved from or written to a Solid Pod.
    /// </summary>
    public sealed class PodResource
    {
        private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> EmptyHeaders =
            new ReadOnlyDictionary<string, IReadOnlyList<string>>(
                new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase));

        /// <summary>
        /// Initializes a new instance of the <see cref="PodResource"/> class.
        /// </summary>
        public PodResource(
            Uri uri,
            byte[]? content,
            string? contentType,
            string? eTag,
            HttpStatusCode statusCode = HttpStatusCode.OK,
            IReadOnlyDictionary<string, IReadOnlyList<string>>? headers = null)
        {
            Uri = uri ?? throw new ArgumentNullException(nameof(uri));
            Content = content ?? Array.Empty<byte>();
            ContentType = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType!;
            ETag = string.IsNullOrWhiteSpace(eTag) ? null : eTag;
            StatusCode = statusCode;
            Headers = headers ?? EmptyHeaders;
        }

        /// <summary>
        /// Gets the canonical HTTP(S) URI of the Solid Pod resource.
        /// </summary>
        public Uri Uri { get; }

        /// <summary>
        /// Gets the raw binary payload of the resource (empty for 204 No Content or 304 Not Modified responses).
        /// </summary>
        public byte[] Content { get; }

        /// <summary>
        /// Gets the HTTP Content-Type header associated with the resource.
        /// </summary>
        public string ContentType { get; }

        /// <summary>
        /// Gets the strong or weak entity tag (<c>ETag</c>) returned by the Solid Pod server, if present.
        /// </summary>
        public string? ETag { get; }

        /// <summary>
        /// Gets the HTTP status code returned by the Solid Pod server.
        /// </summary>
        public HttpStatusCode StatusCode { get; }

        /// <summary>
        /// Gets case-insensitive HTTP response headers associated with this resource response.
        /// </summary>
        public IReadOnlyDictionary<string, IReadOnlyList<string>> Headers { get; }

        /// <summary>
        /// Gets a value indicating whether the server indicated the cached representation was not modified (<c>304 Not Modified</c>).
        /// </summary>
        public bool IsNotModified => StatusCode == HttpStatusCode.NotModified;

        /// <summary>
        /// Gets a value indicating whether the resource media type is a recognized RDF serialization
        /// (<c>text/turtle</c>, <c>text/n3</c>, <c>application/n-triples</c>, or <c>application/ld+json</c>).
        /// </summary>
        public bool IsRdfResource
        {
            get
            {
                string mediaType = ExtractMediaType(ContentType);
                return string.Equals(mediaType, "text/turtle", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(mediaType, "application/x-turtle", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(mediaType, "text/n3", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(mediaType, "application/n-triples", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(mediaType, "application/ld+json", StringComparison.OrdinalIgnoreCase);
            }
        }

        /// <summary>
        /// Decodes <see cref="Content"/> as a UTF-8 string.
        /// </summary>
        public string ContentAsUtf8()
        {
            return Content.Length == 0 ? string.Empty : Encoding.UTF8.GetString(Content);
        }

        private static string ExtractMediaType(string contentType)
        {
            if (string.IsNullOrEmpty(contentType))
            {
                return string.Empty;
            }

            int semicolon = contentType.IndexOf(';');
            string raw = semicolon >= 0 ? contentType.Substring(0, semicolon) : contentType;
            return raw.Trim();
        }
    }

    /// <summary>
    /// Base exception type for Wolin Solid Pod SDK errors.
    /// </summary>
    public class WolinException : Exception
    {
        public WolinException(string message)
            : base(message)
        {
        }

        public WolinException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// Exception thrown when an HTTP request to a Solid Pod or Solid-OIDC endpoint returns a non-success status code.
    /// </summary>
    public sealed class WolinHttpException : WolinException
    {
        public WolinHttpException(
            string message,
            HttpStatusCode statusCode,
            Uri? requestUri = null,
            string? responseBody = null,
            string? dpopNonce = null)
            : base(message)
        {
            StatusCode = statusCode;
            RequestUri = requestUri;
            ResponseBody = responseBody;
            DPoPNonce = dpopNonce;
        }

        /// <summary>
        /// Gets the HTTP status code returned by the server (e.g., 401, 403, 404, 409, 412).
        /// </summary>
        public HttpStatusCode StatusCode { get; }

        /// <summary>
        /// Gets the target request URI that failed.
        /// </summary>
        public Uri? RequestUri { get; }

        /// <summary>
        /// Gets the error response body returned by the server, if available.
        /// </summary>
        public string? ResponseBody { get; }

        /// <summary>
        /// Gets the RFC 9449 <c>DPoP-Nonce</c> challenge header returned by the server, if present.
        /// </summary>
        public string? DPoPNonce { get; }
    }

    /// <summary>
    /// Represents a DPoP-bound token response returned by a Solid-OIDC token endpoint.
    /// </summary>
    public sealed class SolidOidcTokenResponse
    {
        public SolidOidcTokenResponse(
            string accessToken,
            string tokenType,
            string? idToken = null,
            string? refreshToken = null,
            int? expiresIn = null,
            string? scope = null)
        {
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                throw new ArgumentException("Access token must not be empty.", nameof(accessToken));
            }

            AccessToken = accessToken;
            TokenType = string.IsNullOrWhiteSpace(tokenType) ? "DPoP" : tokenType;
            IdToken = idToken;
            RefreshToken = refreshToken;
            ExpiresIn = expiresIn;
            Scope = scope;
        }

        /// <summary>
        /// Gets the DPoP-bound access token.
        /// </summary>
        public string AccessToken { get; }

        /// <summary>
        /// Gets the OAuth 2.0 token type (expected to be <c>DPoP</c> for Solid-OIDC).
        /// </summary>
        public string TokenType { get; }

        /// <summary>
        /// Gets the Solid-OIDC ID token, if issued.
        /// </summary>
        public string? IdToken { get; }

        /// <summary>
        /// Gets the refresh token, if issued.
        /// </summary>
        public string? RefreshToken { get; }

        /// <summary>
        /// Gets the token lifetime in seconds, if specified by the issuer.
        /// </summary>
        public int? ExpiresIn { get; }

        /// <summary>
        /// Gets the granted OAuth 2.0 scopes, if specified by the issuer.
        /// </summary>
        public string? Scope { get; }
    }
}
