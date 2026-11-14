#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;

namespace Wolin.Unity
{
    /// <summary>
    /// Parsed W3C Solid WebID Profile document metadata containing discovered Pod storages,
    /// authorized Solid-OIDC issuers, and Linked Data Notification inboxes.
    /// </summary>
    public sealed class WebIdProfile
    {
        public WebIdProfile(
            string webId,
            IReadOnlyList<string> storages,
            IReadOnlyList<string> oidcIssuers,
            IReadOnlyList<string> inboxes,
            IReadOnlyList<string> types)
        {
            if (string.IsNullOrWhiteSpace(webId))
            {
                throw new ArgumentException("WebID must not be empty.", nameof(webId));
            }

            WebId = webId;
            Storages = storages ?? Array.Empty<string>();
            OidcIssuers = oidcIssuers ?? Array.Empty<string>();
            Inboxes = inboxes ?? Array.Empty<string>();
            Types = types ?? Array.Empty<string>();
        }

        /// <summary>
        /// Gets the canonical WebID URI described by this profile.
        /// </summary>
        public string WebId { get; }

        /// <summary>
        /// Gets all <c>pim:storage</c> (<c>http://www.w3.org/ns/pim/space#storage</c>) root URIs declared for <see cref="WebId"/>.
        /// </summary>
        public IReadOnlyList<string> Storages { get; }

        /// <summary>
        /// Gets all <c>solid:oidcIssuer</c> (<c>http://www.w3.org/ns/solid/terms#oidcIssuer</c>) URIs authorized by <see cref="WebId"/>.
        /// </summary>
        public IReadOnlyList<string> OidcIssuers { get; }

        /// <summary>
        /// Gets all <c>ldp:inbox</c> (<c>http://www.w3.org/ns/ldp#inbox</c>) URIs declared for <see cref="WebId"/>.
        /// </summary>
        public IReadOnlyList<string> Inboxes { get; }

        /// <summary>
        /// Gets all <c>rdf:type</c> IRIs declared for <see cref="WebId"/>.
        /// </summary>
        public IReadOnlyList<string> Types { get; }

        /// <summary>
        /// Gets the primary <c>pim:storage</c> root URI, or <c>null</c> if none is declared in the WebID Profile.
        /// </summary>
        public string? PrimaryStorage => Storages.Count > 0 ? Storages[0] : null;

        /// <summary>
        /// Gets the primary <c>solid:oidcIssuer</c> URI, or <c>null</c> if none is declared in the WebID Profile.
        /// </summary>
        public string? PrimaryOidcIssuer => OidcIssuers.Count > 0 ? OidcIssuers[0] : null;

        /// <summary>
        /// Verifies the Solid-OIDC trust chain (<c>&lt;webid&gt; solid:oidcIssuer &lt;expectedIssuer&gt;</c>).
        /// Throws <see cref="WolinException"/> when the issuer is not authorized by the profile.
        /// </summary>
        public void VerifyOidcIssuer(string expectedIssuer)
        {
            if (string.IsNullOrWhiteSpace(expectedIssuer))
            {
                throw new WolinException("Solid-OIDC expected issuer must not be empty.");
            }

            string trimmed = expectedIssuer.Trim();
            for (int i = 0; i < OidcIssuers.Count; i++)
            {
                if (string.Equals(OidcIssuers[i], trimmed, StringComparison.Ordinal))
                {
                    return;
                }
            }

            throw new WolinException(
                $"Solid-OIDC trust chain verification failed: WebID '{WebId}' does not authorize oidcIssuer '{trimmed}'.");
        }
    }

    /// <summary>
    /// W3C Turtle 1.1 parser for Solid WebID Profile documents (<c>pim:storage</c>, <c>solid:oidcIssuer</c>, and <c>ldp:inbox</c> discovery).
    /// </summary>
    public static class WebIdParser
    {
        public const string PimStorageIri = "http://www.w3.org/ns/pim/space#storage";
        public const string SolidOidcIssuerIri = "http://www.w3.org/ns/solid/terms#oidcIssuer";
        public const string LdpInboxIri = "http://www.w3.org/ns/ldp#inbox";
        public const string RdfTypeIri = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
        public const string FoafPrimaryTopicIri = "http://xmlns.com/foaf/0.1/primaryTopic";

        private const int MaxProfileCharacters = 512 * 1024;

        /// <summary>
        /// Computes the dereferenceable HTTP(S) profile document URL by stripping any fragment identifier (e.g., <c>#me</c>).
        /// </summary>
        public static Uri GetProfileDocumentUri(string webId)
        {
            if (string.IsNullOrWhiteSpace(webId))
            {
                throw new ArgumentException("WebID URI must not be empty.", nameof(webId));
            }

            int hashIndex = webId.IndexOf('#');
            string docUrl = hashIndex >= 0 ? webId.Substring(0, hashIndex) : webId;
            if (!Uri.TryCreate(docUrl, UriKind.Absolute, out Uri? uri)
                || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                throw new WolinException($"Malformed HTTP(S) WebID URI '{webId}'.");
            }

            return uri;
        }

        /// <summary>
        /// Parses a W3C Turtle WebID Profile document and extracts <c>pim:storage</c>, <c>solid:oidcIssuer</c>,
        /// <c>ldp:inbox</c>, and <c>rdf:type</c> triples for <paramref name="webId"/>.
        /// </summary>
        /// <param name="turtle">Raw Turtle RDF document text.</param>
        /// <param name="webId">Target WebID URI (e.g., <c>https://alice.wolin.id/profile/card#me</c>).</param>
        /// <param name="baseIri">Optional base IRI override (defaults to the fragment-stripped <paramref name="webId"/>).</param>
        public static WebIdProfile ParseTurtle(string turtle, string webId, string? baseIri = null)
        {
            if (turtle == null)
            {
                throw new ArgumentNullException(nameof(turtle));
            }

            if (turtle.Length > MaxProfileCharacters)
            {
                throw new WolinException("WebID Profile RDF document exceeds maximum allowed size (512 KiB).");
            }

            if (string.IsNullOrWhiteSpace(webId))
            {
                throw new ArgumentException("WebID URI must not be empty.", nameof(webId));
            }

            Uri defaultBase = string.IsNullOrWhiteSpace(baseIri)
                ? GetProfileDocumentUri(webId)
                : ParseBaseUri(baseIri!);

            var parser = new TurtleReader(turtle, defaultBase);
            List<RdfTriple> triples = parser.ParseAllTriples();

            string targetSubject = ResolveTargetSubject(webId.Trim(), defaultBase, triples);

            var storages = new List<string>();
            var oidcIssuers = new List<string>();
            var inboxes = new List<string>();
            var types = new List<string>();

            var seenStorages = new HashSet<string>(StringComparer.Ordinal);
            var seenIssuers = new HashSet<string>(StringComparer.Ordinal);
            var seenInboxes = new HashSet<string>(StringComparer.Ordinal);
            var seenTypes = new HashSet<string>(StringComparer.Ordinal);

            for (int i = 0; i < triples.Count; i++)
            {
                RdfTriple triple = triples[i];
                if (!triple.ObjectIsIri || !string.Equals(triple.Subject, targetSubject, StringComparison.Ordinal))
                {
                    continue;
                }

                switch (triple.Predicate)
                {
                    case PimStorageIri:
                        if (seenStorages.Add(triple.ObjectValue))
                        {
                            storages.Add(triple.ObjectValue);
                        }

                        break;

                    case SolidOidcIssuerIri:
                        if (seenIssuers.Add(triple.ObjectValue))
                        {
                            oidcIssuers.Add(triple.ObjectValue);
                        }

                        break;

                    case LdpInboxIri:
                        if (seenInboxes.Add(triple.ObjectValue))
                        {
                            inboxes.Add(triple.ObjectValue);
                        }

                        break;

                    case RdfTypeIri:
                        if (seenTypes.Add(triple.ObjectValue))
                        {
                            types.Add(triple.ObjectValue);
                        }

                        break;
                }
            }

            return new WebIdProfile(
                targetSubject,
                new ReadOnlyCollection<string>(storages),
                new ReadOnlyCollection<string>(oidcIssuers),
                new ReadOnlyCollection<string>(inboxes),
                new ReadOnlyCollection<string>(types));
        }

        private static string ResolveTargetSubject(string webId, Uri docUri, List<RdfTriple> triples)
        {
            for (int i = 0; i < triples.Count; i++)
            {
                if (string.Equals(triples[i].Subject, webId, StringComparison.Ordinal))
                {
                    return webId;
                }
            }

            // If a document URL without fragment was supplied and the document defines foaf:primaryTopic, follow it.
            if (webId.IndexOf('#') < 0)
            {
                string docIri = docUri.AbsoluteUri;
                for (int i = 0; i < triples.Count; i++)
                {
                    RdfTriple t = triples[i];
                    if (t.ObjectIsIri
                        && string.Equals(t.Subject, docIri, StringComparison.Ordinal)
                        && string.Equals(t.Predicate, FoafPrimaryTopicIri, StringComparison.Ordinal))
                    {
                        return t.ObjectValue;
                    }
                }
            }

            return webId;
        }

        private static Uri ParseBaseUri(string rawBase)
        {
            if (!Uri.TryCreate(rawBase, UriKind.Absolute, out Uri? parsed))
            {
                throw new WolinException($"Invalid Turtle base IRI '{rawBase}'.");
            }

            return parsed;
        }

        private readonly struct RdfTriple
        {
            public RdfTriple(string subject, string predicate, string objectValue, bool objectIsIri)
            {
                Subject = subject;
                Predicate = predicate;
                ObjectValue = objectValue;
                ObjectIsIri = objectIsIri;
            }

            public string Subject { get; }
            public string Predicate { get; }
            public string ObjectValue { get; }
            public bool ObjectIsIri { get; }
        }

        private readonly struct RdfTerm
        {
            public RdfTerm(string value, bool isIri)
            {
                Value = value;
                IsIri = isIri;
            }

            public string Value { get; }
            public bool IsIri { get; }
        }

        private sealed class TurtleReader
        {
            private readonly string _src;
            private readonly Dictionary<string, string> _prefixes = new Dictionary<string, string>(StringComparer.Ordinal);
            private readonly List<RdfTriple> _triples = new List<RdfTriple>();
            private Uri _baseUri;
            private int _pos;
            private int _blankCounter;

            public TurtleReader(string src, Uri baseUri)
            {
                _src = src;
                _baseUri = baseUri;
            }

            public List<RdfTriple> ParseAllTriples()
            {
                while (true)
                {
                    SkipWhitespaceAndComments();
                    if (_pos >= _src.Length)
                    {
                        break;
                    }

                    if (TryReadDirective())
                    {
                        continue;
                    }

                    ParseTriplesStatement();
                }

                return _triples;
            }

            private bool TryReadDirective()
            {
                if (PeekChar() == '@')
                {
                    if (MatchExact("@prefix") && IsDelimiterAt(_pos + 7))
                    {
                        _pos += 7;
                        SkipWhitespaceAndComments();
                        string prefix = ReadPrefixLabel();
                        SkipWhitespaceAndComments();
                        string nsIri = ReadIriRef();
                        SkipWhitespaceAndComments();
                        ExpectChar('.');
                        _prefixes[prefix] = nsIri;
                        return true;
                    }

                    if (MatchExact("@base") && IsDelimiterAt(_pos + 5))
                    {
                        _pos += 5;
                        SkipWhitespaceAndComments();
                        string newBase = ReadIriRef();
                        SkipWhitespaceAndComments();
                        ExpectChar('.');
                        _baseUri = ParseBaseUri(newBase);
                        return true;
                    }
                }
                else if (MatchIgnoreCase("PREFIX") && IsWhitespaceOrIriAt(_pos + 6))
                {
                    _pos += 6;
                    SkipWhitespaceAndComments();
                    string prefix = ReadPrefixLabel();
                    SkipWhitespaceAndComments();
                    string nsIri = ReadIriRef();
                    _prefixes[prefix] = nsIri;
                    return true;
                }
                else if (MatchIgnoreCase("BASE") && IsWhitespaceOrIriAt(_pos + 4))
                {
                    _pos += 4;
                    SkipWhitespaceAndComments();
                    string newBase = ReadIriRef();
                    _baseUri = ParseBaseUri(newBase);
                    return true;
                }

                return false;
            }

            private void ParseTriplesStatement()
            {
                SkipWhitespaceAndComments();
                if (PeekChar() == '[')
                {
                    string bnode = ParseBlankNodePropertyList();
                    SkipWhitespaceAndComments();
                    if (PeekChar() != '.')
                    {
                        ParsePredicateObjectList(bnode);
                    }

                    SkipWhitespaceAndComments();
                    ExpectChar('.');
                    return;
                }

                RdfTerm subject = ReadTerm(allowLiteral: false);
                SkipWhitespaceAndComments();
                ParsePredicateObjectList(subject.Value);
                SkipWhitespaceAndComments();
                ExpectChar('.');
            }

            private void ParsePredicateObjectList(string subject)
            {
                while (true)
                {
                    SkipWhitespaceAndComments();
                    char next = PeekChar();
                    if (next == '.' || next == ']' || next == '\0')
                    {
                        return;
                    }

                    string predicate = ReadVerb();
                    ParseObjectList(subject, predicate);

                    SkipWhitespaceAndComments();
                    if (PeekChar() == ';')
                    {
                        while (PeekChar() == ';')
                        {
                            _pos++;
                            SkipWhitespaceAndComments();
                        }

                        char afterSemi = PeekChar();
                        if (afterSemi == '.' || afterSemi == ']')
                        {
                            return;
                        }
                    }
                    else
                    {
                        return;
                    }
                }
            }

            private void ParseObjectList(string subject, string predicate)
            {
                while (true)
                {
                    SkipWhitespaceAndComments();
                    RdfTerm obj = ReadTerm(allowLiteral: true);
                    _triples.Add(new RdfTriple(subject, predicate, obj.Value, obj.IsIri));

                    SkipWhitespaceAndComments();
                    if (PeekChar() == ',')
                    {
                        _pos++;
                    }
                    else
                    {
                        return;
                    }
                }
            }

            private string ReadVerb()
            {
                SkipWhitespaceAndComments();
                if (PeekChar() == 'a' && IsVerbBoundaryAt(_pos + 1))
                {
                    _pos++;
                    return RdfTypeIri;
                }

                RdfTerm pred = ReadTerm(allowLiteral: false);
                if (!pred.IsIri)
                {
                    throw new WolinException("Turtle predicate must be an IRI or 'a'.");
                }

                return pred.Value;
            }

            private RdfTerm ReadTerm(bool allowLiteral)
            {
                SkipWhitespaceAndComments();
                if (_pos >= _src.Length)
                {
                    throw new WolinException("Unexpected end of Turtle document while reading RDF term.");
                }

                char c = _src[_pos];
                if (c == '<')
                {
                    return new RdfTerm(ReadIriRef(), isIri: true);
                }

                if (c == '[')
                {
                    string bnode = ParseBlankNodePropertyList();
                    return new RdfTerm(bnode, isIri: false);
                }

                if (c == '(')
                {
                    string head = ParseCollection();
                    bool isNil = string.Equals(head, "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil", StringComparison.Ordinal);
                    return new RdfTerm(head, isIri: isNil);
                }

                if (c == '_' && _pos + 1 < _src.Length && _src[_pos + 1] == ':')
                {
                    return new RdfTerm(ReadBlankNodeLabel(), isIri: false);
                }

                if (c == '"' || c == '\'')
                {
                    if (!allowLiteral)
                    {
                        throw new WolinException("String literal is not permitted in subject or predicate position.");
                    }

                    return new RdfTerm(ReadQuotedLiteral(), isIri: false);
                }

                if (allowLiteral && (char.IsDigit(c) || ((c == '+' || c == '-' || c == '.') && _pos + 1 < _src.Length && char.IsDigit(_src[_pos + 1]))))
                {
                    return new RdfTerm(ReadNumericLiteral(), isIri: false);
                }

                if (allowLiteral)
                {
                    if (MatchExact("true") && IsTermBoundaryAt(_pos + 4))
                    {
                        _pos += 4;
                        return new RdfTerm("true", isIri: false);
                    }

                    if (MatchExact("false") && IsTermBoundaryAt(_pos + 5))
                    {
                        _pos += 5;
                        return new RdfTerm("false", isIri: false);
                    }
                }

                return new RdfTerm(ReadPrefixedName(), isIri: true);
            }

            private string ParseBlankNodePropertyList()
            {
                ExpectChar('[');
                string bnode = NewBlankNode();
                SkipWhitespaceAndComments();
                if (PeekChar() != ']')
                {
                    ParsePredicateObjectList(bnode);
                    SkipWhitespaceAndComments();
                }

                ExpectChar(']');
                return bnode;
            }

            private string ParseCollection()
            {
                const string rdfFirst = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
                const string rdfRest = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
                const string rdfNil = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";

                ExpectChar('(');
                SkipWhitespaceAndComments();
                if (PeekChar() == ')')
                {
                    _pos++;
                    return rdfNil;
                }

                string head = NewBlankNode();
                string current = head;
                while (true)
                {
                    RdfTerm item = ReadTerm(allowLiteral: true);
                    _triples.Add(new RdfTriple(current, rdfFirst, item.Value, item.IsIri));
                    SkipWhitespaceAndComments();
                    if (PeekChar() == ')')
                    {
                        _pos++;
                        _triples.Add(new RdfTriple(current, rdfRest, rdfNil, objectIsIri: true));
                        break;
                    }

                    string nextNode = NewBlankNode();
                    _triples.Add(new RdfTriple(current, rdfRest, nextNode, objectIsIri: false));
                    current = nextNode;
                }

                return head;
            }

            private string ReadPrefixLabel()
            {
                int start = _pos;
                while (_pos < _src.Length && _src[_pos] != ':' && !char.IsWhiteSpace(_src[_pos]))
                {
                    _pos++;
                }

                string label = _src.Substring(start, _pos - start);
                ExpectChar(':');
                return label;
            }

            private string ReadPrefixedName()
            {
                int colonIndex = -1;
                int start = _pos;
                while (_pos < _src.Length)
                {
                    char c = _src[_pos];
                    if (c == '\\' && _pos + 1 < _src.Length)
                    {
                        _pos += 2;
                        continue;
                    }

                    if (c == ':' && colonIndex < 0)
                    {
                        colonIndex = _pos;
                        _pos++;
                        continue;
                    }

                    if (char.IsWhiteSpace(c) || c == ';' || c == ',' || c == '<' || c == '>' || c == '"' || c == '\'' || c == '[' || c == ']' || c == '(' || c == ')' || c == '#')
                    {
                        break;
                    }

                    if (c == '.')
                    {
                        // A trailing dot terminates a statement unless followed by a valid PN_LOCAL character.
                        if (_pos + 1 >= _src.Length || IsTermBoundaryAt(_pos + 1) || _src[_pos + 1] == '.')
                        {
                            break;
                        }
                    }

                    _pos++;
                }

                if (colonIndex < start)
                {
                    string unexpected = _src.Substring(start, Math.Min(16, _src.Length - start));
                    throw new WolinException($"Malformed Turtle prefixed name near '{unexpected}'.");
                }

                string prefix = _src.Substring(start, colonIndex - start);
                string rawLocal = _src.Substring(colonIndex + 1, _pos - (colonIndex + 1));
                if (!_prefixes.TryGetValue(prefix, out string? nsIri))
                {
                    throw new WolinException($"Undeclared Turtle prefix '{prefix}:'.");
                }

                string unescapedLocal = UnescapePrefixedLocal(rawLocal);
                return string.Concat(nsIri, unescapedLocal);
            }

            private static string UnescapePrefixedLocal(string raw)
            {
                if (raw.IndexOf('\\') < 0)
                {
                    return raw;
                }

                var sb = new StringBuilder(raw.Length);
                for (int i = 0; i < raw.Length; i++)
                {
                    if (raw[i] == '\\' && i + 1 < raw.Length)
                    {
                        i++;
                    }

                    sb.Append(raw[i]);
                }

                return sb.ToString();
            }

            private string ReadBlankNodeLabel()
            {
                _pos += 2; // skip "_:"
                int start = _pos;
                while (_pos < _src.Length)
                {
                    char c = _src[_pos];
                    if (char.IsWhiteSpace(c) || c == ';' || c == ',' || c == ']' || c == ')' || c == '#')
                    {
                        break;
                    }

                    if (c == '.' && (_pos + 1 >= _src.Length || IsTermBoundaryAt(_pos + 1)))
                    {
                        break;
                    }

                    _pos++;
                }

                if (_pos == start)
                {
                    throw new WolinException("Empty blank node label '_:' in Turtle document.");
                }

                return "_:" + _src.Substring(start, _pos - start);
            }

            private string ReadQuotedLiteral()
            {
                char quote = _src[_pos];
                bool longQuote = _pos + 2 < _src.Length && _src[_pos + 1] == quote && _src[_pos + 2] == quote;
                _pos += longQuote ? 3 : 1;

                var sb = new StringBuilder();
                bool closed = false;
                while (_pos < _src.Length)
                {
                    char c = _src[_pos];
                    if (c == '\\')
                    {
                        _pos++;
                        if (_pos >= _src.Length)
                        {
                            throw new WolinException("Unterminated escape sequence in Turtle string literal.");
                        }

                        sb.Append(ReadEscapedChar());
                        continue;
                    }

                    if (longQuote)
                    {
                        if (c == quote && _pos + 2 < _src.Length && _src[_pos + 1] == quote && _src[_pos + 2] == quote)
                        {
                            _pos += 3;
                            closed = true;
                            break;
                        }
                    }
                    else if (c == quote)
                    {
                        _pos++;
                        closed = true;
                        break;
                    }
                    else if (c == '\n' || c == '\r')
                    {
                        throw new WolinException("Unescaped newline inside single-quoted Turtle literal.");
                    }

                    sb.Append(c);
                    _pos++;
                }

                if (!closed)
                {
                    throw new WolinException("Unterminated string literal in Turtle document.");
                }

                // Consume optional language tag (@en) or datatype (^^<...> or ^^prefix:local)
                if (_pos < _src.Length && _src[_pos] == '@')
                {
                    _pos++;
                    while (_pos < _src.Length && (char.IsLetterOrDigit(_src[_pos]) || _src[_pos] == '-'))
                    {
                        _pos++;
                    }
                }
                else if (_pos + 1 < _src.Length && _src[_pos] == '^' && _src[_pos + 1] == '^')
                {
                    _pos += 2;
                    SkipWhitespaceAndComments();
                    if (PeekChar() == '<')
                    {
                        _ = ReadIriRef();
                    }
                    else
                    {
                        _ = ReadPrefixedName();
                    }
                }

                return sb.ToString();
            }

            private string ReadNumericLiteral()
            {
                int start = _pos;
                if (_src[_pos] == '+' || _src[_pos] == '-')
                {
                    _pos++;
                }

                while (_pos < _src.Length)
                {
                    char c = _src[_pos];
                    if (char.IsDigit(c) || c == 'e' || c == 'E' || c == '+' || c == '-')
                    {
                        _pos++;
                        continue;
                    }

                    if (c == '.' && _pos + 1 < _src.Length && char.IsDigit(_src[_pos + 1]))
                    {
                        _pos++;
                        continue;
                    }

                    break;
                }

                return _src.Substring(start, _pos - start);
            }

            private string ReadIriRef()
            {
                ExpectChar('<');
                var sb = new StringBuilder();
                bool closed = false;
                while (_pos < _src.Length)
                {
                    char c = _src[_pos];
                    if (c == '>')
                    {
                        _pos++;
                        closed = true;
                        break;
                    }

                    if (c == '\\')
                    {
                        _pos++;
                        if (_pos >= _src.Length || (_src[_pos] != 'u' && _src[_pos] != 'U'))
                        {
                            throw new WolinException("Invalid escape sequence inside Turtle IRIref.");
                        }

                        sb.Append(ReadEscapedChar());
                        continue;
                    }

                    if (c <= 0x20 || c == '<' || c == '"' || c == '{' || c == '}' || c == '|' || c == '^' || c == '`')
                    {
                        throw new WolinException($"Disallowed character '{c}' inside Turtle IRIref.");
                    }

                    sb.Append(c);
                    _pos++;
                }

                if (!closed)
                {
                    throw new WolinException("Unterminated '<...>' IRIref in Turtle document.");
                }

                return ResolveIri(sb.ToString());
            }

            private string ResolveIri(string rawIri)
            {
                if (rawIri.Length == 0)
                {
                    // Empty relative IRI <> resolves to the document base IRI without any fragment.
                    string baseStr = _baseUri.AbsoluteUri;
                    int hashIdx = baseStr.IndexOf('#');
                    return hashIdx >= 0 ? baseStr.Substring(0, hashIdx) : baseStr;
                }

                if (rawIri[0] == '#')
                {
                    string baseStr = _baseUri.AbsoluteUri;
                    int hashIdx = baseStr.IndexOf('#');
                    string docPart = hashIdx >= 0 ? baseStr.Substring(0, hashIdx) : baseStr;
                    return string.Concat(docPart, rawIri);
                }

                if (Uri.TryCreate(rawIri, UriKind.Absolute, out Uri? abs) && HasExplicitScheme(rawIri))
                {
                    return abs.AbsoluteUri;
                }

                if (!Uri.TryCreate(_baseUri, rawIri, out Uri? resolved))
                {
                    throw new WolinException($"Failed to resolve relative IRI '{rawIri}' against base '{_baseUri}'.");
                }

                return resolved.AbsoluteUri;
            }

            private static bool HasExplicitScheme(string rawIri)
            {
                int colon = rawIri.IndexOf(':');
                if (colon <= 0)
                {
                    return false;
                }

                if (!char.IsLetter(rawIri[0]))
                {
                    return false;
                }

                for (int i = 1; i < colon; i++)
                {
                    char c = rawIri[i];
                    if (!char.IsLetterOrDigit(c) && c != '+' && c != '-' && c != '.')
                    {
                        return false;
                    }
                }

                return true;
            }

            private string ReadEscapedChar()
            {
                char esc = _src[_pos++];
                switch (esc)
                {
                    case 't': return "\t";
                    case 'b': return "\b";
                    case 'n': return "\n";
                    case 'r': return "\r";
                    case 'f': return "\f";
                    case '"': return "\"";
                    case '\'': return "'";
                    case '\\': return "\\";
                    case 'u':
                        return ReadUnicodeScalar(4);
                    case 'U':
                        return ReadUnicodeScalar(8);
                    default:
                        throw new WolinException($"Unsupported escape '\\{esc}' in Turtle literal.");
                }
            }

            private string ReadUnicodeScalar(int hexDigits)
            {
                if (_pos + hexDigits > _src.Length)
                {
                    throw new WolinException("Truncated Unicode escape in Turtle document.");
                }

                string hex = _src.Substring(_pos, hexDigits);
                _pos += hexDigits;
                if (!int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int codePoint))
                {
                    throw new WolinException($"Invalid Unicode escape '\\u{hex}' in Turtle document.");
                }

                return char.ConvertFromUtf32(codePoint);
            }

            private void SkipWhitespaceAndComments()
            {
                while (_pos < _src.Length)
                {
                    char c = _src[_pos];
                    if (char.IsWhiteSpace(c))
                    {
                        _pos++;
                        continue;
                    }

                    if (c == '#')
                    {
                        while (_pos < _src.Length && _src[_pos] != '\n' && _src[_pos] != '\r')
                        {
                            _pos++;
                        }

                        continue;
                    }

                    break;
                }
            }

            private char PeekChar()
            {
                return _pos < _src.Length ? _src[_pos] : '\0';
            }

            private void ExpectChar(char expected)
            {
                if (_pos >= _src.Length || _src[_pos] != expected)
                {
                    char actual = _pos < _src.Length ? _src[_pos] : '\0';
                    throw new WolinException($"Expected '{expected}' in Turtle document at offset {_pos}, found '{actual}'.");
                }

                _pos++;
            }

            private bool MatchExact(string token)
            {
                return _pos + token.Length <= _src.Length
                    && string.CompareOrdinal(_src, _pos, token, 0, token.Length) == 0;
            }

            private bool MatchIgnoreCase(string token)
            {
                return _pos + token.Length <= _src.Length
                    && string.Compare(_src, _pos, token, 0, token.Length, StringComparison.OrdinalIgnoreCase) == 0;
            }

            private bool IsDelimiterAt(int index)
            {
                return index < _src.Length && (char.IsWhiteSpace(_src[index]) || _src[index] == '<');
            }

            private bool IsWhitespaceOrIriAt(int index)
            {
                return index < _src.Length && (char.IsWhiteSpace(_src[index]) || _src[index] == '<' || _src[index] == '#');
            }

            private bool IsVerbBoundaryAt(int index)
            {
                if (index >= _src.Length)
                {
                    return true;
                }

                char c = _src[index];
                return char.IsWhiteSpace(c) || c == '<' || c == '[' || c == '(' || c == '"' || c == '\'' || c == '#';
            }

            private bool IsTermBoundaryAt(int index)
            {
                if (index >= _src.Length)
                {
                    return true;
                }

                char c = _src[index];
                return char.IsWhiteSpace(c) || c == '.' || c == ';' || c == ',' || c == ']' || c == ')' || c == '#';
            }

            private string NewBlankNode()
            {
                _blankCounter++;
                return "_:b" + _blankCounter.ToString(CultureInfo.InvariantCulture);
            }
        }
    }
}
