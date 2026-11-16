#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Wolin.Unity.Tests
{
    [TestFixture]
    public sealed class WolinClientTests
    {
        [Test]
        public void Base64Url_RoundTripsRfc4648VectorsAndRejectsInvalidInput()
        {
            Assert.That(DPoPSigner.Base64UrlEncode(Array.Empty<byte>()), Is.EqualTo(string.Empty));
            Assert.That(DPoPSigner.Base64UrlDecode(string.Empty), Is.Empty);

            byte[][] samples =
            {
                new byte[] { 0xfb },
                new byte[] { 0xfb, 0xff },
                new byte[] { 0xfb, 0xff, 0xfe },
                Encoding.UTF8.GetBytes("wolin-solid-pod-engine-0.11")
            };

            foreach (byte[] sample in samples)
            {
                string encoded = DPoPSigner.Base64UrlEncode(sample);
                Assert.That(encoded.Contains('='), Is.False);
                Assert.That(encoded.Contains('+'), Is.False);
                Assert.That(encoded.Contains('/'), Is.False);

                byte[] decoded = DPoPSigner.Base64UrlDecode(encoded);
                Assert.That(decoded, Is.EqualTo(sample));
            }

            // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
            string abcHash = DPoPSigner.Sha256Base64Url(Encoding.ASCII.GetBytes("abc"));
            Assert.That(abcHash, Is.EqualTo("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"));

            Assert.Throws<FormatException>(() => DPoPSigner.Base64UrlDecode("abc+def"));
            Assert.Throws<FormatException>(() => DPoPSigner.Base64UrlDecode("abc/def"));
            Assert.Throws<FormatException>(() => DPoPSigner.Base64UrlDecode("a"));
        }

        [Test]
        public void DPoPSigner_GeneratesValidEs256ProofAndRfc7638Thumbprint()
        {
            using var signer = new DPoPSigner();

            Assert.That(signer.Algorithm, Is.EqualTo("ES256"));
            Assert.That(signer.KeyType, Is.EqualTo("EC"));
            Assert.That(signer.Curve, Is.EqualTo("P-256"));
            Assert.That(DPoPSigner.Base64UrlDecode(signer.X).Length, Is.EqualTo(32));
            Assert.That(DPoPSigner.Base64UrlDecode(signer.Y).Length, Is.EqualTo(32));

            string publicJwk = signer.ExportPublicJwkJson();
            Assert.That(publicJwk, Does.Contain("\"kty\":\"EC\""));
            Assert.That(publicJwk, Does.Contain("\"crv\":\"P-256\""));
            Assert.That(publicJwk, Does.Not.Contain("\"d\":"));

            string expectedThumbprint = DPoPSigner.ComputeEcJwkThumbprint("P-256", signer.X, signer.Y);
            Assert.That(signer.JwkThumbprint, Is.EqualTo(expectedThumbprint));

            var issuedAt = new DateTimeOffset(2026, 11, 15, 0, 0, 0, TimeSpan.Zero);
            const string token = "eyJhbGciOiJFUzI1NiJ9.access-token-payload.sig";
            string proof = signer.CreateProof(
                "get",
                "https://Alice.Wolin.id:443/pod/game/save.ttl?cache=0#state",
                accessToken: token,
                nonce: "srv-nonce-42",
                issuedAt: issuedAt,
                jti: "fixed-jti-001");

            Assert.That(signer.VerifyProofSignature(proof), Is.True);

            string[] segments = proof.Split('.');
            Assert.That(segments.Length, Is.EqualTo(3));

            string headerJson = Encoding.UTF8.GetString(DPoPSigner.Base64UrlDecode(segments[0]));
            string payloadJson = Encoding.UTF8.GetString(DPoPSigner.Base64UrlDecode(segments[1]));
            byte[] signatureBytes = DPoPSigner.Base64UrlDecode(segments[2]);

            Assert.That(signatureBytes.Length, Is.EqualTo(64));
            Assert.That(headerJson, Does.Contain("\"typ\":\"dpop+jwt\""));
            Assert.That(headerJson, Does.Contain("\"alg\":\"ES256\""));
            Assert.That(headerJson, Does.Contain(publicJwk));

            Assert.That(payloadJson, Does.Contain("\"htm\":\"GET\""));
            Assert.That(payloadJson, Does.Contain("\"htu\":\"https://alice.wolin.id/pod/game/save.ttl\""));
            Assert.That(payloadJson, Does.Contain($"\"iat\":{issuedAt.ToUnixTimeSeconds()}"));
            Assert.That(payloadJson, Does.Contain("\"jti\":\"fixed-jti-001\""));
            Assert.That(payloadJson, Does.Contain($"\"ath\":\"{DPoPSigner.ComputeAccessTokenHash(token)}\""));
            Assert.That(payloadJson, Does.Contain("\"nonce\":\"srv-nonce-42\""));

            // Independent verification reconstructing public key solely from exported JWK coordinates
            var pubParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = DPoPSigner.Base64UrlDecode(signer.X),
                    Y = DPoPSigner.Base64UrlDecode(signer.Y)
                }
            };

            using var verifier = ECDsa.Create(pubParams);
            byte[] signingInput = Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]);
            Assert.That(verifier.VerifyData(signingInput, signatureBytes, HashAlgorithmName.SHA256), Is.True);

            // Tampering with payload invalidates signature
            string tamperedPayload = DPoPSigner.Base64UrlEncode(Encoding.UTF8.GetBytes("{\"htm\":\"DELETE\"}"));
            string tamperedJwt = segments[0] + "." + tamperedPayload + "." + segments[2];
            Assert.That(signer.VerifyProofSignature(tamperedJwt), Is.False);
        }

        [Test]
        public void DPoPSigner_NormalizeHtu_PreservesCustomPortAndStripsQueryAndFragment()
        {
            string normalizedCustom = DPoPSigner.NormalizeHtu(new Uri("http://127.0.0.1:4000/pods/alice/profile/card?foo=bar#me"));
            Assert.That(normalizedCustom, Is.EqualTo("http://127.0.0.1:4000/pods/alice/profile/card"));

            string normalizedDefaultHttp = DPoPSigner.NormalizeHtu(new Uri("http://example.org:80/a/b"));
            Assert.That(normalizedDefaultHttp, Is.EqualTo("http://example.org/a/b"));

            string p1;
            string p2;
            using (var signer = DPoPSigner.Generate())
            {
                p1 = signer.CreateProof("GET", "https://pod.wolin.id/item");
                p2 = signer.CreateProof("GET", "https://pod.wolin.id/item");
            }

            Assert.That(p1, Is.Not.EqualTo(p2), "Consecutive DPoP proofs must embed distinct random jti values.");
        }

        [Test]
        public void WebIdParser_ExtractsStorageOidcIssuerAndInboxFromTurtleProfile()
        {
            const string turtle = @"
                # Wolin Solid WebID Profile Document
                @prefix foaf: <http://xmlns.com/foaf/0.1/> .
                @prefix solid: <http://www.w3.org/ns/solid/terms#> .
                @prefix pim: <http://www.w3.org/ns/pim/space#> .
                @prefix ldp: <http://www.w3.org/ns/ldp#> .

                <> a foaf:PersonalProfileDocument ;
                   foaf:maker <#me> ;
                   foaf:primaryTopic <#me> .

                <#me>
                    a foaf:Person ;
                    foaf:name ""Alice # Not A Comment""@en ;
                    solid:oidcIssuer <https://auth.wolin.id> , <https://backup-idp.example.org> ;
                    pim:storage </> , <https://vault.wolin.id/alice/> ;
                    solid:account [
                        a solid:Account ;
                        foaf:Note """"""Multiline
                        profile note with ; and . inside quotes""""""
                    ] ;
                    ldp:inbox <../inbox/> ;
                .
            ";

            const string webId = "https://alice.wolin.id/profile/card#me";
            WebIdProfile profile = WebIdParser.ParseTurtle(turtle, webId);

            Assert.That(profile.WebId, Is.EqualTo(webId));
            Assert.That(profile.PrimaryStorage, Is.EqualTo("https://alice.wolin.id/"));
            Assert.That(profile.Storages, Is.EquivalentTo(new[]
            {
                "https://alice.wolin.id/",
                "https://vault.wolin.id/alice/"
            }));
            Assert.That(profile.PrimaryOidcIssuer, Is.EqualTo("https://auth.wolin.id/"));
            Assert.That(profile.OidcIssuers, Does.Contain("https://backup-idp.example.org/"));
            Assert.That(profile.Inboxes, Is.EqualTo(new[] { "https://alice.wolin.id/inbox/" }));
            Assert.That(profile.Types, Does.Contain("http://xmlns.com/foaf/0.1/Person"));

            Assert.DoesNotThrow(() => profile.VerifyOidcIssuer("https://auth.wolin.id/"));
            Assert.Throws<WolinException>(() => profile.VerifyOidcIssuer("https://rogue-idp.example.com/"));
        }

        [Test]
        public void WebIdParser_SupportsSparqlPrefixAndBaseDirectives()
        {
            const string turtle = @"
                BASE <https://bob.wolin.id/profile/card>
                PREFIX space: <http://www.w3.org/ns/pim/space#>
                PREFIX solid: <http://www.w3.org/ns/solid/terms#>

                <#me> solid:oidcIssuer <https://auth.wolin.id> ;
                      space:storage </pod/> .
            ";

            WebIdProfile profile = WebIdParser.ParseTurtle(turtle, "https://bob.wolin.id/profile/card#me");
            Assert.That(profile.PrimaryStorage, Is.EqualTo("https://bob.wolin.id/pod/"));
            Assert.That(profile.PrimaryOidcIssuer, Is.EqualTo("https://auth.wolin.id/"));
        }

        [Test]
        public async Task WolinClient_DiscoverStorageAndPerformAuthenticatedLdpCrudWithETags()
        {
            var recordedRequests = new List<CapturedRequest>();
            string currentPayload = "@prefix ex: <https://example.org/> . <#save> ex:level 1 .";
            string currentETag = "\"etag-v1\"";
            bool deleted = false;

            var handler = new StubHttpMessageHandler((req, bodyBytes) =>
            {
                recordedRequests.Add(CapturedRequest.From(req, bodyBytes));
                string url = req.RequestUri!.AbsoluteUri;

                if (req.Method == HttpMethod.Get && url == "https://alice.wolin.id/profile/card")
                {
                    const string profileTtl = @"
                        @prefix pim: <http://www.w3.org/ns/pim/space#> .
                        @prefix solid: <http://www.w3.org/ns/solid/terms#> .
                        <#me> solid:oidcIssuer <https://auth.wolin.id> ;
                              pim:storage <https://alice.wolin.id/> .
                    ";
                    var resp = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(profileTtl, Encoding.UTF8, "text/turtle")
                    };
                    resp.Headers.ETag = new EntityTagHeaderValue("\"profile-v1\"");
                    return resp;
                }

                if (url == "https://alice.wolin.id/games/wolin/save.ttl")
                {
                    if (req.Method == HttpMethod.Get)
                    {
                        if (deleted)
                        {
                            return new HttpResponseMessage(HttpStatusCode.NotFound);
                        }

                        if (req.Headers.TryGetValues("If-None-Match", out IEnumerable<string>? inm)
                            && inm.Contains(currentETag))
                        {
                            var notMod = new HttpResponseMessage(HttpStatusCode.NotModified);
                            notMod.Headers.ETag = new EntityTagHeaderValue(currentETag);
                            return notMod;
                        }

                        var ok = new HttpResponseMessage(HttpStatusCode.OK)
                        {
                            Content = new StringContent(currentPayload, Encoding.UTF8, "text/turtle")
                        };
                        ok.Headers.ETag = new EntityTagHeaderValue(currentETag);
                        return ok;
                    }

                    if (req.Method == HttpMethod.Put)
                    {
                        if (req.Headers.TryGetValues("If-Match", out IEnumerable<string>? im))
                        {
                            string matchVal = im.First();
                            if (matchVal != currentETag)
                            {
                                return new HttpResponseMessage(HttpStatusCode.PreconditionFailed)
                                {
                                    Content = new StringContent("ETag mismatch", Encoding.UTF8, "text/plain")
                                };
                            }
                        }

                        currentPayload = Encoding.UTF8.GetString(bodyBytes);
                        currentETag = "\"etag-v2\"";
                        var updated = new HttpResponseMessage(HttpStatusCode.NoContent);
                        updated.Headers.ETag = new EntityTagHeaderValue(currentETag);
                        return updated;
                    }

                    if (req.Method == HttpMethod.Delete)
                    {
                        if (req.Headers.TryGetValues("If-Match", out IEnumerable<string>? im)
                            && im.First() != currentETag)
                        {
                            return new HttpResponseMessage(HttpStatusCode.PreconditionFailed);
                        }

                        deleted = true;
                        return new HttpResponseMessage(HttpStatusCode.NoContent);
                    }
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

            using var httpClient = new HttpClient(handler);
            using var client = new WolinClient(httpClient, disposeHttpClient: false);
            client.SetAccessToken("solid-access-token-xyz", "https://alice.wolin.id/profile/card#me");

            // 1. Discover pim:storage from WebID (#me stripped on wire)
            Uri storageRoot = await client.DiscoverStorageAsync("https://alice.wolin.id/profile/card#me");
            Assert.That(storageRoot.AbsoluteUri, Is.EqualTo("https://alice.wolin.id/"));

            var resourceUri = new Uri(storageRoot, "games/wolin/save.ttl");

            // 2. GET resource + ETag
            PodResource initial = await client.GetAsync(resourceUri);
            Assert.That(initial.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(initial.ETag, Is.EqualTo("\"etag-v1\""));
            Assert.That(initial.IsRdfResource, Is.True);
            Assert.That(initial.ContentAsUtf8(), Does.Contain("ex:level 1"));

            // Verify Authorization: DPoP + DPoP proof headers on GET
            CapturedRequest getCapture = recordedRequests.Last();
            Assert.That(getCapture.AuthorizationScheme, Is.EqualTo("DPoP"));
            Assert.That(getCapture.AuthorizationParameter, Is.EqualTo("solid-access-token-xyz"));
            Assert.That(getCapture.DpopHeader, Is.Not.Null.And.Not.Empty);
            Assert.That(client.DPoPSigner.VerifyProofSignature(getCapture.DpopHeader!), Is.True);

            // 3. Conditional GET with matching ETag returns 304 Not Modified
            PodResource cached = await client.GetAsync(resourceUri, ifNoneMatch: initial.ETag);
            Assert.That(cached.IsNotModified, Is.True);
            Assert.That(cached.Content, Is.Empty);
            Assert.That(cached.ETag, Is.EqualTo("\"etag-v1\""));

            // 4. Conditional PUT with stale ETag fails with 412 Precondition Failed
            WolinHttpException? conflict = Assert.ThrowsAsync<WolinHttpException>(async () =>
                await client.PutAsync(
                    resourceUri,
                    "@prefix ex: <https://example.org/> . <#save> ex:level 99 .",
                    contentType: "text/turtle",
                    ifMatch: "\"stale-etag\""));
            Assert.That(conflict!.StatusCode, Is.EqualTo(HttpStatusCode.PreconditionFailed));

            // 5. Conditional PUT with current ETag succeeds and returns new ETag
            PodResource updatedRes = await client.PutAsync(
                resourceUri,
                "@prefix ex: <https://example.org/> . <#save> ex:level 2 .",
                contentType: "text/turtle",
                ifMatch: "etag-v1"); // unquoted ETag is normalized automatically to "etag-v1"
            Assert.That(updatedRes.ETag, Is.EqualTo("\"etag-v2\""));

            PodResource reread = await client.GetAsync(resourceUri);
            Assert.That(reread.ContentAsUtf8(), Does.Contain("ex:level 2"));
            Assert.That(reread.ETag, Is.EqualTo("\"etag-v2\""));

            // 6. Conditional DELETE with matching ETag deletes resource
            await client.DeleteAsync(resourceUri, ifMatch: reread.ETag);

            WolinHttpException? notFound = Assert.ThrowsAsync<WolinHttpException>(async () =>
                await client.GetAsync(resourceUri));
            Assert.That(notFound!.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
        }

        [Test]
        public async Task WolinClient_AutomaticallyRetriesDpopNonceChallengeAndExchangesCode()
        {
            int tokenAttempts = 0;
            int resourceAttempts = 0;

            var handler = new StubHttpMessageHandler((req, _) =>
            {
                string dpop = req.Headers.GetValues("DPoP").Single();
                string payloadJson = Encoding.UTF8.GetString(DPoPSigner.Base64UrlDecode(dpop.Split('.')[1]));

                if (req.RequestUri!.AbsoluteUri == "https://auth.wolin.id/oauth/token")
                {
                    tokenAttempts++;
                    Assert.That(payloadJson, Does.Not.Contain("\"ath\":"), "Token endpoint DPoP proof must not carry ath.");

                    if (tokenAttempts == 1)
                    {
                        var challenge = new HttpResponseMessage(HttpStatusCode.BadRequest)
                        {
                            Content = new StringContent("{\"error\":\"use_dpop_nonce\"}", Encoding.UTF8, "application/json")
                        };
                        challenge.Headers.TryAddWithoutValidation("DPoP-Nonce", "idp-nonce-001");
                        return challenge;
                    }

                    Assert.That(payloadJson, Does.Contain("\"nonce\":\"idp-nonce-001\""));
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(
                            "{\"access_token\":\"issued-dpop-token\",\"token_type\":\"DPoP\",\"id_token\":\"eyJ.id.sig\",\"expires_in\":1800}",
                            Encoding.UTF8,
                            "application/json")
                    };
                }

                if (req.RequestUri.AbsoluteUri == "https://alice.wolin.id/private/notes.ttl")
                {
                    resourceAttempts++;
                    if (resourceAttempts == 1)
                    {
                        var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                        challenge.Headers.TryAddWithoutValidation("DPoP-Nonce", "pod-nonce-999");
                        return challenge;
                    }

                    Assert.That(payloadJson, Does.Contain("\"nonce\":\"pod-nonce-999\""));
                    Assert.That(payloadJson, Does.Contain("\"ath\":"));
                    var ok = new HttpResponseMessage(HttpStatusCode.Created);
                    ok.Headers.ETag = new EntityTagHeaderValue("\"created-v1\"");
                    return ok;
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

            using var httpClient = new HttpClient(handler);
            using var client = new WolinClient(httpClient);

            SolidOidcTokenResponse tokenResp = await client.ExchangeAuthorizationCodeAsync(
                new Uri("https://auth.wolin.id/oauth/token"),
                clientId: "unity-game-client",
                code: "auth-code-123",
                redirectUri: "wolin://callback",
                codeVerifier: "pkce-verifier-abcdef0123456789");

            Assert.That(tokenAttempts, Is.EqualTo(2));
            Assert.That(tokenResp.AccessToken, Is.EqualTo("issued-dpop-token"));
            Assert.That(tokenResp.TokenType, Is.EqualTo("DPoP"));
            Assert.That(tokenResp.ExpiresIn, Is.EqualTo(1800));
            Assert.That(client.AccessToken, Is.EqualTo("issued-dpop-token"));

            PodResource created = await client.PutAsync(
                "https://alice.wolin.id/private/notes.ttl",
                "<#note> <https://example.org/text> \"Hello Solid\" .",
                contentType: "text/turtle",
                createOnly: true);

            Assert.That(resourceAttempts, Is.EqualTo(2));
            Assert.That(created.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That(created.ETag, Is.EqualTo("\"created-v1\""));
            Assert.That(client.DPoPNonce, Is.EqualTo("pod-nonce-999"));
        }

        [Test]
        public void PodIdValidation_EnforcesLengthCharsetHyphenAndReservedRules()
        {
            Assert.That(WolinClient.DefaultAuthUrl, Is.EqualTo("https://auth.wolin.id"));
            Assert.That(WolinClient.DefaultPodUrl, Is.EqualTo("https://pod.wolin.id"));

            string[] validHandles = { "bob", "alice", "alice-01", new string('a', 32), "team-alpha-2026" };
            foreach (string valid in validHandles)
            {
                Assert.That(WolinClient.IsValidPodId(valid), Is.True, valid);
                Assert.That(WolinClient.ValidatePodId(valid), Is.EqualTo(valid));
            }

            string[] invalidHandles =
            {
                "", "a", "ab", new string('a', 33), "Alice", "-alice", "alice-",
                "alice--dev", "xn--p1ai", "alice_01", "alice.dev",
                "auth", "pod", "pods", "api", "admin", "wolin", "www"
            };
            foreach (string invalid in invalidHandles)
            {
                Assert.That(WolinClient.IsValidPodId(invalid), Is.False, invalid);
                Assert.Throws<WolinException>(() => WolinClient.ValidatePodId(invalid));
            }
        }

        [Test]
        public async Task WolinClient_Follows302SignedAssetRedirectWithoutLeakingAuthOrDpopHeaders()
        {
            var recorded = new List<CapturedRequest>();
            byte[] assetBytes = Encoding.UTF8.GetBytes("wolin-signed-r2-asset-binary-payload");

            var handler = new StubHttpMessageHandler((req, bodyBytes) =>
            {
                recorded.Add(CapturedRequest.From(req, bodyBytes));
                string url = req.RequestUri!.AbsoluteUri;

                if (url == "https://pod.wolin.id/pods/alice/media/model.glb")
                {
                    Assert.That(req.Headers.Authorization?.Scheme, Is.EqualTo("DPoP"));
                    Assert.That(req.Headers.Contains("DPoP"), Is.True);

                    var redirect = new HttpResponseMessage(HttpStatusCode.Found);
                    redirect.Headers.Location = new Uri("https://auth.wolin.id/assets/alice/media/model.glb?exp=1763500060&sig=ok");
                    redirect.Headers.ETag = new EntityTagHeaderValue("\"asset-etag-v1\"");
                    redirect.Headers.TryAddWithoutValidation("Link", "<http://www.w3.org/ns/ldp#NonRDFSource>; rel=\"type\"");
                    return redirect;
                }

                if (url == "https://auth.wolin.id/assets/alice/media/model.glb?exp=1763500060&sig=ok")
                {
                    if (req.Headers.Authorization != null || req.Headers.Contains("DPoP"))
                    {
                        return new HttpResponseMessage(HttpStatusCode.BadRequest)
                        {
                            Content = new StringContent("Leaked Authorization or DPoP header to external asset CDN")
                        };
                    }

                    var ok = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(assetBytes)
                    };
                    ok.Content.Headers.ContentType = new MediaTypeHeaderValue("model/gltf-binary");
                    return ok;
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

            using var httpClient = new HttpClient(handler);
            using var client = new WolinClient(httpClient);
            client.SetAccessToken("solid-oidc-dpop-token", "https://alice.wolin.id/profile/card#me");

            PodResource asset = await client.GetAsync(
                "https://pod.wolin.id/pods/alice/media/model.glb",
                accept: "model/gltf-binary");

            Assert.That(asset.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(asset.Content, Is.EqualTo(assetBytes));
            Assert.That(asset.ContentType, Is.EqualTo("model/gltf-binary"));
            Assert.That(asset.ETag, Is.EqualTo("\"asset-etag-v1\""));
            Assert.That(asset.Headers.ContainsKey("Link"), Is.True);

            Assert.That(recorded.Count, Is.EqualTo(2));
            Assert.That(recorded[1].AuthorizationScheme, Is.Null);
            Assert.That(recorded[1].DpopHeader, Is.Null);
        }

        private sealed class CapturedRequest
        {
            public string Method { get; private set; } = string.Empty;
            public string Url { get; private set; } = string.Empty;
            public string? AuthorizationScheme { get; private set; }
            public string? AuthorizationParameter { get; private set; }
            public string? DpopHeader { get; private set; }
            public byte[] Body { get; private set; } = Array.Empty<byte>();

            public static CapturedRequest From(HttpRequestMessage req, byte[] body)
            {
                string? dpop = null;
                if (req.Headers.TryGetValues("DPoP", out IEnumerable<string>? vals))
                {
                    dpop = vals.FirstOrDefault();
                }

                return new CapturedRequest
                {
                    Method = req.Method.Method,
                    Url = req.RequestUri?.AbsoluteUri ?? string.Empty,
                    AuthorizationScheme = req.Headers.Authorization?.Scheme,
                    AuthorizationParameter = req.Headers.Authorization?.Parameter,
                    DpopHeader = dpop,
                    Body = body
                };
            }
        }

        private sealed class StubHttpMessageHandler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, byte[], HttpResponseMessage> _responder;

            public StubHttpMessageHandler(Func<HttpRequestMessage, byte[], HttpResponseMessage> responder)
            {
                _responder = responder;
            }

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                byte[] body = request.Content == null
                    ? Array.Empty<byte>()
                    : await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                return _responder(request, body);
            }
        }
    }
}
