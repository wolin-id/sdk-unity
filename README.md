<div align="center">

# Wolin Unity SDK (`id.wolin.unity`)

**Official C# Unity Package Manager (UPM) SDK for Wolin & W3C Solid 0.11 Pods**

</div>

---

`id.wolin.unity` provides a zero-dependency, `async`/`await` (`Task`-based) C# client for integrating Unity 2022.3+ games, XR spatial apps, and interactive simulations with [Wolin](https://wolin.id) and any standards-compliant **W3C Solid 0.11** Pod server.

## Features

- **RFC 9449 DPoP (`ES256`) + Solid-OIDC**: Ephemeral or caller-managed NIST P-256 `ECDsa` proof-of-possession JWT signing, RFC 7638 SHA-256 JWK thumbprints (`jkt`), `ath` access-token binding, PKCE authorization-code exchange, and automatic `DPoP-Nonce` challenge-retry.
- **WebID Profile & `pim:storage` Discovery**: Built-in W3C Turtle 1.1 parser (`WebIdParser`) extracting `pim:storage`, `solid:oidcIssuer`, `ldp:inbox`, and `rdf:type` triples with RFC 3986 relative IRI resolution.
- **Solid LDP CRUD with `ETag` Concurrency**: `GET`, `PUT`, and `DELETE` operations supporting `If-Match` optimistic concurrency, `If-None-Match` conditional reads (`304 Not Modified`), and atomic create-only writes (`If-None-Match: *`).
- **Pure `.NET Standard 2.1` / C# 9.0**: Built strictly on `System.Net.Http.HttpClient` and `System.Security.Cryptography.ECDsa` with zero external NuGet dependencies.

## Installation (Unity 2022.3+)

### Option A: Unity Package Manager (Git URL)

1. Open **Window > Package Manager** in Unity.
2. Click **+ > Add package from git URL...**
3. Enter:

```text
https://github.com/wolin-id/sdk-unity.git
```

### Option B: `Packages/manifest.json`

Add `id.wolin.unity` to your project's `Packages/manifest.json`:

```json
{
  "dependencies": {
    "id.wolin.unity": "https://github.com/wolin-id/sdk-unity.git#v0.1.0"
  }
}
```

## Quickstart

```csharp
using System;
using System.Threading.Tasks;
using Wolin.Unity;

public static class SaveGameSync
{
    public static async Task SyncSaveAsync(string webId, string accessToken)
    {
        using var client = new WolinClient();
        client.SetAccessToken(accessToken, webId);

        // 1. Dereference WebID Profile & discover pim:storage root
        Uri storageRoot = await client.DiscoverStorageAsync(webId);
        Uri saveUri = new Uri(storageRoot, "games/my-rpg/save.ttl");

        // 2. Write Turtle RDF resource to the player's Solid Pod
        const string initialSave = @"
            @prefix ex: <https://example.org/rpg#> .
            <#player> ex:level 5 ; ex:gold 1200 .
        ";
        PodResource created = await client.PutAsync(
            saveUri,
            initialSave,
            contentType: "text/turtle");

        // 3. Read back with ETag and perform optimistic compare-and-swap update
        PodResource loaded = await client.GetAsync(saveUri);
        PodResource updated = await client.PutAsync(
            saveUri,
            "@prefix ex: <https://example.org/rpg#> .\n<#player> ex:level 6 ; ex:gold 1550 .\n",
            contentType: "text/turtle",
            ifMatch: loaded.ETag);

        // 4. Conditional delete using latest ETag
        await client.DeleteAsync(saveUri, ifMatch: updated.ETag);
    }
}
```

## Package Layout

```text
sdk-unity/
├── package.json                          # UPM manifest (id.wolin.unity v0.1.0, Unity 2022.3+)
├── Runtime/
│   ├── Wolin.Unity.asmdef                # Runtime assembly definition
│   ├── WolinClient.cs                    # Solid-OIDC + LDP CRUD async HttpClient
│   ├── DPoPSigner.cs                     # RFC 9449 ES256 proof & RFC 7638 JWK thumbprint
│   ├── WebIdParser.cs                    # W3C Turtle 1.1 WebID Profile & pim:storage parser
│   └── PodResource.cs                    # Resource payload, ETag, and HTTP error models
└── Tests/
    └── Editor/
        ├── Wolin.Unity.Tests.asmdef      # Unity EditMode Test Runner assembly definition
        └── WolinClientTests.cs           # NUnit 3 test suite
```

## Running Tests Locally (.NET CLI)

The repository includes a hidden `DotNet~/` solution (ignored by Unity's AssetDatabase) that compiles `Runtime/` against `netstandard2.1` (`LangVersion 9.0`) and runs `Tests/Editor/` under NUnit 3:

```bash
dotnet test DotNet~/Wolin.Unity.sln --configuration Release
```

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

Copyright (c) 2026 [Entropy Paradox, Inc.](https://wolin.id) and Wolin Contributors.
