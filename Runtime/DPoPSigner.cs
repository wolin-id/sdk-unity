#nullable enable
using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Wolin.Unity
{
    /// <summary>
    /// RFC 9449 OAuth 2.0 Demonstrating Proof-of-Possession (DPoP) proof generator
    /// using NIST P-256 ECDSA with SHA-256 (<c>ES256</c>) and RFC 7638 JWK Thumbprints (<c>jkt</c>).
    /// </summary>
    public sealed class DPoPSigner : IDisposable
    {
        private const int P256CoordinateSizeBytes = 32;
        private const int Es256SignatureSizeBytes = 64;
        private const int DefaultJtiSizeBytes = 16;

        private readonly ECDsa _ecdsa;
        private readonly bool _ownsKey;
        private readonly string _publicJwkJson;
        private readonly string _encodedJwtHeader;
        private bool _disposed;

        /// <summary>
        /// Initializes a new <see cref="DPoPSigner"/> with a freshly generated ephemeral NIST P-256 keypair.
        /// </summary>
        public DPoPSigner()
            : this(ECDsa.Create(ECCurve.NamedCurves.nistP256), leaveOpen: false)
        {
            _ownsKey = true;
        }

        /// <summary>
        /// Initializes a new <see cref="DPoPSigner"/> wrapping an existing NIST P-256 <see cref="ECDsa"/> key.
        /// </summary>
        /// <param name="ecdsa">An <see cref="ECDsa"/> instance configured on curve <c>nistP256</c> (256-bit).</param>
        /// <param name="leaveOpen">If <c>true</c>, disposing this signer will not dispose <paramref name="ecdsa"/>.</param>
        public DPoPSigner(ECDsa ecdsa, bool leaveOpen = false)
        {
            _ecdsa = ecdsa ?? throw new ArgumentNullException(nameof(ecdsa));
            if (_ecdsa.KeySize != 256)
            {
                throw new ArgumentException(
                    $"RFC 9449 ES256 requires a 256-bit P-256 ECDsa key, but got {_ecdsa.KeySize}-bit.",
                    nameof(ecdsa));
            }

            _ownsKey = !leaveOpen;

            ECParameters pubParams = _ecdsa.ExportParameters(includePrivateParameters: false);
            if (pubParams.Q.X == null || pubParams.Q.Y == null)
            {
                throw new CryptographicException("ECDsa key did not export valid public Q.X / Q.Y coordinates.");
            }

            byte[] xBytes = NormalizeFixedBigEndian(pubParams.Q.X, P256CoordinateSizeBytes);
            byte[] yBytes = NormalizeFixedBigEndian(pubParams.Q.Y, P256CoordinateSizeBytes);

            X = Base64UrlEncode(xBytes);
            Y = Base64UrlEncode(yBytes);

            // RFC 7638 §3.1 canonical lexicographical JSON representation for EC public keys:
            // {"crv":"P-256","kty":"EC","x":"...","y":"..."}
            _publicJwkJson = string.Concat(
                "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"",
                X,
                "\",\"y\":\"",
                Y,
                "\"}");

            JwkThumbprint = Sha256Base64Url(Encoding.UTF8.GetBytes(_publicJwkJson));

            string headerJson = string.Concat(
                "{\"alg\":\"ES256\",\"jwk\":",
                _publicJwkJson,
                ",\"typ\":\"dpop+jwt\"}");
            _encodedJwtHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        }

        /// <summary>
        /// Gets the JWS algorithm identifier (<c>ES256</c>).
        /// </summary>
        public string Algorithm => "ES256";

        /// <summary>
        /// Gets the JWK key type (<c>EC</c>).
        /// </summary>
        public string KeyType => "EC";

        /// <summary>
        /// Gets the JWK curve identifier (<c>P-256</c>).
        /// </summary>
        public string Curve => "P-256";

        /// <summary>
        /// Gets the unpadded Base64URL-encoded 32-byte public X coordinate.
        /// </summary>
        public string X { get; }

        /// <summary>
        /// Gets the unpadded Base64URL-encoded 32-byte public Y coordinate.
        /// </summary>
        public string Y { get; }

        /// <summary>
        /// Gets the RFC 7638 SHA-256 JWK Thumbprint (<c>jkt</c>) encoded as unpadded Base64URL.
        /// </summary>
        public string JwkThumbprint { get; }

        /// <summary>
        /// Generates a new ephemeral NIST P-256 <see cref="DPoPSigner"/>.
        /// </summary>
        public static DPoPSigner Generate()
        {
            return new DPoPSigner();
        }

        /// <summary>
        /// Exports the public key as a canonical RFC 7517 / RFC 7638 JSON Web Key (never includes private key parameters).
        /// </summary>
        public string ExportPublicJwkJson()
        {
            ThrowIfDisposed();
            return _publicJwkJson;
        }

        /// <summary>
        /// Creates a compact-serialized RFC 9449 DPoP proof JWT signed with ES256.
        /// </summary>
        public string CreateProof(
            string httpMethod,
            string targetUrl,
            string? accessToken = null,
            string? nonce = null,
            DateTimeOffset? issuedAt = null,
            string? jti = null)
        {
            if (string.IsNullOrWhiteSpace(targetUrl))
            {
                throw new ArgumentException("Target URL must not be empty.", nameof(targetUrl));
            }

            if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out Uri? targetUri))
            {
                throw new ArgumentException($"Invalid absolute HTTP(S) URI '{targetUrl}'.", nameof(targetUrl));
            }

            return CreateProof(httpMethod, targetUri, accessToken, nonce, issuedAt, jti);
        }

        /// <summary>
        /// Creates a compact-serialized RFC 9449 DPoP proof JWT signed with ES256.
        /// </summary>
        /// <param name="httpMethod">HTTP method name (e.g., <c>GET</c>, <c>PUT</c>, <c>DELETE</c>, <c>POST</c>).</param>
        /// <param name="targetUri">Target HTTP(S) request URI (query and fragment are stripped per RFC 9449 §4.2).</param>
        /// <param name="accessToken">Optional access token to bind via the <c>ath</c> SHA-256 claim.</param>
        /// <param name="nonce">Optional server-supplied <c>DPoP-Nonce</c> value.</param>
        /// <param name="issuedAt">Optional timestamp override (defaults to <see cref="DateTimeOffset.UtcNow"/>).</param>
        /// <param name="jti">Optional unique token identifier override (defaults to 128-bit cryptographic random Base64URL).</param>
        public string CreateProof(
            string httpMethod,
            Uri targetUri,
            string? accessToken = null,
            string? nonce = null,
            DateTimeOffset? issuedAt = null,
            string? jti = null)
        {
            ThrowIfDisposed();

            if (string.IsNullOrWhiteSpace(httpMethod))
            {
                throw new ArgumentException("HTTP method must not be empty.", nameof(httpMethod));
            }

            if (targetUri == null)
            {
                throw new ArgumentNullException(nameof(targetUri));
            }

            string normalizedHtm = httpMethod.Trim().ToUpperInvariant();
            string normalizedHtu = NormalizeHtu(targetUri);
            string effectiveJti = string.IsNullOrEmpty(jti) ? GenerateJti() : ValidateJti(jti!);
            long iat = (issuedAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();

            var payloadBuilder = new StringBuilder(256);
            payloadBuilder.Append('{');
            payloadBuilder.Append("\"htm\":");
            AppendJsonString(payloadBuilder, normalizedHtm);
            payloadBuilder.Append(",\"htu\":");
            AppendJsonString(payloadBuilder, normalizedHtu);
            payloadBuilder.Append(",\"iat\":");
            payloadBuilder.Append(iat.ToString(CultureInfo.InvariantCulture));
            payloadBuilder.Append(",\"jti\":");
            AppendJsonString(payloadBuilder, effectiveJti);

            if (!string.IsNullOrEmpty(accessToken))
            {
                string ath = ComputeAccessTokenHash(accessToken!);
                payloadBuilder.Append(",\"ath\":");
                AppendJsonString(payloadBuilder, ath);
            }

            if (!string.IsNullOrEmpty(nonce))
            {
                payloadBuilder.Append(",\"nonce\":");
                AppendJsonString(payloadBuilder, nonce!);
            }

            payloadBuilder.Append('}');

            string encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadBuilder.ToString()));
            string signingInput = string.Concat(_encodedJwtHeader, ".", encodedPayload);
            byte[] signingBytes = Encoding.ASCII.GetBytes(signingInput);

            // In .NET Standard 2.0/2.1 and .NET 5+, ECDsa.SignData(byte[], HashAlgorithmName)
            // produces IEEE P1363 fixed-field concatenation (r || s, 64 bytes for P-256).
            byte[] signature = _ecdsa.SignData(signingBytes, HashAlgorithmName.SHA256);
            if (signature.Length != Es256SignatureSizeBytes)
            {
                throw new CryptographicException(
                    $"Unexpected ES256 signature length {signature.Length} (expected {Es256SignatureSizeBytes} bytes).");
            }

            string encodedSignature = Base64UrlEncode(signature);
            return string.Concat(signingInput, ".", encodedSignature);
        }

        /// <summary>
        /// Verifies the cryptographic ES256 signature of a compact DPoP JWT against this signer's public P-256 key.
        /// </summary>
        public bool VerifyProofSignature(string dpopJwt)
        {
            ThrowIfDisposed();

            if (string.IsNullOrWhiteSpace(dpopJwt))
            {
                return false;
            }

            string[] parts = dpopJwt.Split('.');
            if (parts.Length != 3
                || parts[0].Length == 0
                || parts[1].Length == 0
                || parts[2].Length == 0)
            {
                return false;
            }

            byte[] signature;
            try
            {
                signature = Base64UrlDecode(parts[2]);
            }
            catch (FormatException)
            {
                return false;
            }

            if (signature.Length != Es256SignatureSizeBytes)
            {
                return false;
            }

            byte[] signingInput = Encoding.ASCII.GetBytes(string.Concat(parts[0], ".", parts[1]));
            return _ecdsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256);
        }

        /// <summary>
        /// Computes the RFC 9449 §4.2 <c>ath</c> claim (unpadded Base64URL of the SHA-256 digest of the ASCII access token).
        /// </summary>
        public static string ComputeAccessTokenHash(string accessToken)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new ArgumentException("Access token must not be null or empty.", nameof(accessToken));
            }

            return Sha256Base64Url(Encoding.ASCII.GetBytes(accessToken));
        }

        /// <summary>
        /// Computes the RFC 7638 §3.1 SHA-256 JWK Thumbprint for EC P-256 Base64URL coordinates.
        /// </summary>
        public static string ComputeEcJwkThumbprint(string crv, string xBase64Url, string yBase64Url)
        {
            if (string.IsNullOrEmpty(crv))
            {
                throw new ArgumentException("Curve must not be empty.", nameof(crv));
            }

            if (string.IsNullOrEmpty(xBase64Url))
            {
                throw new ArgumentException("X coordinate must not be empty.", nameof(xBase64Url));
            }

            if (string.IsNullOrEmpty(yBase64Url))
            {
                throw new ArgumentException("Y coordinate must not be empty.", nameof(yBase64Url));
            }

            _ = Base64UrlDecode(xBase64Url);
            _ = Base64UrlDecode(yBase64Url);

            var sb = new StringBuilder(160);
            sb.Append("{\"crv\":");
            AppendJsonString(sb, crv);
            sb.Append(",\"kty\":\"EC\",\"x\":");
            AppendJsonString(sb, xBase64Url);
            sb.Append(",\"y\":");
            AppendJsonString(sb, yBase64Url);
            sb.Append('}');

            return Sha256Base64Url(Encoding.UTF8.GetBytes(sb.ToString()));
        }

        /// <summary>
        /// Normalizes an HTTP(S) target URI for the RFC 9449 <c>htu</c> claim by stripping query and fragment components,
        /// lowercasing scheme and host, and omitting default ports (<c>:80</c> for HTTP, <c>:443</c> for HTTPS).
        /// </summary>
        public static string NormalizeHtu(Uri targetUri)
        {
            if (targetUri == null)
            {
                throw new ArgumentNullException(nameof(targetUri));
            }

            if (!targetUri.IsAbsoluteUri)
            {
                throw new ArgumentException("DPoP target URI must be an absolute HTTP or HTTPS URI.", nameof(targetUri));
            }

            string scheme = targetUri.Scheme.ToLowerInvariant();
            if (scheme != "http" && scheme != "https")
            {
                throw new ArgumentException(
                    $"DPoP target URI scheme must be 'http' or 'https', got '{targetUri.Scheme}'.",
                    nameof(targetUri));
            }

            if (!string.IsNullOrEmpty(targetUri.UserInfo))
            {
                throw new ArgumentException("Userinfo credentials are forbidden in DPoP target URIs.", nameof(targetUri));
            }

            string host = targetUri.HostNameType == UriHostNameType.IPv6
                ? targetUri.Host.ToLowerInvariant()
                : targetUri.IdnHost.ToLowerInvariant();

            string portPart = targetUri.IsDefaultPort
                ? string.Empty
                : ":" + targetUri.Port.ToString(CultureInfo.InvariantCulture);

            string path = string.IsNullOrEmpty(targetUri.AbsolutePath) ? "/" : targetUri.AbsolutePath;
            return string.Concat(scheme, "://", host, portPart, path);
        }

        /// <summary>
        /// Computes a SHA-256 digest and encodes it using RFC 4648 §5 unpadded Base64URL.
        /// </summary>
        public static string Sha256Base64Url(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using (var sha256 = SHA256.Create())
            {
                byte[] digest = sha256.ComputeHash(data);
                return Base64UrlEncode(digest);
            }
        }

        /// <summary>
        /// Encodes a byte array using RFC 4648 §5 unpadded Base64URL.
        /// </summary>
        public static string Base64UrlEncode(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (data.Length == 0)
            {
                return string.Empty;
            }

            string base64 = Convert.ToBase64String(data);
            int end = base64.Length;
            while (end > 0 && base64[end - 1] == '=')
            {
                end--;
            }

            var chars = new char[end];
            for (int i = 0; i < end; i++)
            {
                char c = base64[i];
                chars[i] = c switch
                {
                    '+' => '-',
                    '/' => '_',
                    _ => c
                };
            }

            return new string(chars);
        }

        /// <summary>
        /// Decodes an unpadded (or padded) RFC 4648 §5 Base64URL string into bytes.
        /// </summary>
        public static byte[] Base64UrlDecode(string input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (input.Length == 0)
            {
                return Array.Empty<byte>();
            }

            string trimmed = input.TrimEnd('=');
            int mod = trimmed.Length % 4;
            if (mod == 1)
            {
                throw new FormatException("Invalid Base64URL input length.");
            }

            int padCount = mod == 0 ? 0 : 4 - mod;
            var chars = new char[trimmed.Length + padCount];
            for (int i = 0; i < trimmed.Length; i++)
            {
                char c = trimmed[i];
                if (c == '+')
                {
                    throw new FormatException("Invalid '+' character in Base64URL string.");
                }

                if (c == '/')
                {
                    throw new FormatException("Invalid '/' character in Base64URL string.");
                }

                chars[i] = c switch
                {
                    '-' => '+',
                    '_' => '/',
                    _ => c
                };
            }

            for (int i = 0; i < padCount; i++)
            {
                chars[trimmed.Length + i] = '=';
            }

            return Convert.FromBase64CharArray(chars, 0, chars.Length);
        }

        /// <summary>
        /// Releases the underlying <see cref="ECDsa"/> key if owned by this signer.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_ownsKey)
            {
                _ecdsa.Dispose();
            }
        }

        internal static void AppendJsonString(StringBuilder sb, string value)
        {
            sb.Append('"');
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                switch (c)
                {
                    case '"':
                        sb.Append("\\\"");
                        break;
                    case '\\':
                        sb.Append("\\\\");
                        break;
                    case '\b':
                        sb.Append("\\b");
                        break;
                    case '\f':
                        sb.Append("\\f");
                        break;
                    case '\n':
                        sb.Append("\\n");
                        break;
                    case '\r':
                        sb.Append("\\r");
                        break;
                    case '\t':
                        sb.Append("\\t");
                        break;
                    default:
                        if (c < 0x20)
                        {
                            sb.Append("\\u");
                            sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.Append(c);
                        }

                        break;
                }
            }

            sb.Append('"');
        }

        private static string GenerateJti()
        {
            var bytes = new byte[DefaultJtiSizeBytes];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            return Base64UrlEncode(bytes);
        }

        private static string ValidateJti(string jti)
        {
            string trimmed = jti.Trim();
            if (trimmed.Length == 0 || trimmed.Length > 256)
            {
                throw new ArgumentException("DPoP 'jti' must be between 1 and 256 characters.", nameof(jti));
            }

            for (int i = 0; i < trimmed.Length; i++)
            {
                if (char.IsControl(trimmed[i]))
                {
                    throw new ArgumentException("DPoP 'jti' must not contain control characters.", nameof(jti));
                }
            }

            return trimmed;
        }

        private static byte[] NormalizeFixedBigEndian(byte[] coordinate, int expectedLength)
        {
            if (coordinate.Length == expectedLength)
            {
                return coordinate;
            }

            if (coordinate.Length > expectedLength)
            {
                int offset = coordinate.Length - expectedLength;
                for (int i = 0; i < offset; i++)
                {
                    if (coordinate[i] != 0)
                    {
                        throw new CryptographicException("EC coordinate exceeds expected P-256 byte length.");
                    }
                }

                var sliced = new byte[expectedLength];
                Buffer.BlockCopy(coordinate, offset, sliced, 0, expectedLength);
                return sliced;
            }

            var padded = new byte[expectedLength];
            Buffer.BlockCopy(coordinate, 0, padded, expectedLength - coordinate.Length, coordinate.Length);
            return padded;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(DPoPSigner));
            }
        }
    }
}
