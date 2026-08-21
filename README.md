# GO_BNLS

A modern, cross-platform, open-source implementation of the BNLS (Battle.net
Logon Server) protocol — a maintained, MIT-licensed replacement for
[JBLS](https://github.com/Davnit/JBLS), the long-standing reference server,
which has no explicit open-source license and runs on an aging Java version.

GO_BNLS aims to answer the same requests JBLS does — CD-key hashing, password
hashing (both the legacy and NLS/SRP login systems), and CheckRevision
version-checking for classic Battle.net titles — as a single dependency-free
binary per platform, built to be easy to run and maintain for years.

## Status

Early scaffold. Not yet functional — see [Roadmap](#roadmap).

## Provenance

This is a **clean-room implementation**, built from
[bnetdocs.org](https://bnetdocs.org)'s published protocol documentation
(the [BNLS Packet Guide](https://bnetdocs.org/document/22/bnls-packet-guide),
[BNLS Product Codes](https://bnetdocs.org/document/44/bnls-product-codes),
and [CheckRevision](https://bnetdocs.org/document/47/checkrevision) documents,
among others), not ported or copied from JBLS or any other existing BNLS
implementation's source. Opcode numbers were cross-checked against an
independent, differently-licensed reference
([cbls](https://github.com/scottanderson/cbls)) for corroboration only.

Some of the underlying crypto (CRC32, the BNLS_AUTHORIZE checksum, classic/
modern CD-key decoding, Blizzard's "broken SHA-1") started from working,
tested implementations in a companion C# project
([Invigoration](https://github.com/tagban/invigoration)) and was ported to Go
— reusing already-solved, already-verified math rather than re-deriving it,
while every line here is original Go code.

## Scope

Implements every opcode a bot client or a Battle.net-compatible server sends
to BNLS — the full protocol, not a subset tailored to one client. See the
opcode table below for current status.

**Explicitly out of scope**: `BNLS_WARDEN` (0x7D) — official Battle.net's
live anti-cheat proxying. This project targets private-server and bot use,
where Warden doesn't apply.

### Opcode support

| Hex | Opcode | Status |
|---|---|---|
| 0x00 | BNLS_NULL | planned |
| 0x01 | BNLS_CDKEY | planned |
| 0x02 | BNLS_LOGONCHALLENGE | planned |
| 0x03 | BNLS_LOGONPROOF | planned |
| 0x04 | BNLS_CREATEACCOUNT | planned |
| 0x05 | BNLS_CHANGECHALLENGE | planned |
| 0x06 | BNLS_CHANGEPROOF | planned |
| 0x07 | BNLS_UPGRADECHALLENGE | planned |
| 0x08 | BNLS_UPGRADEPROOF | planned |
| 0x09 | BNLS_VERSIONCHECK | planned |
| 0x0A | BNLS_CONFIRMLOGON | planned |
| 0x0B | BNLS_HASHDATA | planned |
| 0x0C | BNLS_CDKEY_EX | planned |
| 0x0D | BNLS_CHOOSENLSREVISION | planned |
| 0x0E | BNLS_AUTHORIZE | planned |
| 0x0F | BNLS_AUTHORIZEPROOF | planned |
| 0x10 | BNLS_REQUESTVERSIONBYTE | planned |
| 0x11 | BNLS_VERIFYSERVER | planned |
| 0x12 | BNLS_RESERVESERVERSLOTS | planned |
| 0x13 | BNLS_SERVERLOGONCHALLENGE | planned |
| 0x14 | BNLS_SERVERLOGONPROOF | planned |
| 0x18 | BNLS_VERSIONCHECKEX | planned |
| 0x1A | BNLS_VERSIONCHECKEX2 | planned |
| 0x7D | BNLS_WARDEN | out of scope |
| 0xFF | BNLS_IPBAN | planned (unofficial, not core spec) |

### Product support (target)

StarCraft, StarCraft: Brood War, StarCraft (Japanese), StarCraft
(Shareware), Warcraft II: Battle.net Edition, Diablo (Retail + Shareware),
Diablo II, Diablo II: Lord of Destruction, Warcraft III: Reign of Chaos,
Warcraft III: The Frozen Throne, Warcraft III: Demo.

## Why self-host a BNLS server at all

Public BNLS servers compute CheckRevision (version-check) replies against
*their own* copy of each game's files. If a private Battle.net server you're
connecting through is pinned to an older patch than the public BNLS server
has on hand, authentication fails with "Invalid game version" — no client-
side setting fixes this, since the exact game-file checksums have to match.
Self-hosting lets you point the server at the exact patch files your target
server expects.

## Building from source

Requires [Go](https://go.dev/dl/) 1.25+.

```bash
go build ./...
go test ./...
```

## Configuration

See `configs/openbnls.example.json`. Game-file profiles live under a
configured `profilesDirectory` — **this project never downloads or bundles
game files**; you supply your own legitimately-owned copies. See
`docs/profiles.md` (coming with Phase 1) for the manifest format.

## Roadmap

- **Phase 0** (this commit): repo scaffold, CI, licensing.
- **Phase 1**: core opcodes + CheckRevision + the 10 non-NLS products.
- **Phase 2**: Warcraft III/TFT — NLS/SRP login and the 26-character CD-key format.
- **Phase 3**: remaining bot-facing opcodes, connection stats endpoint, a
  version-profile-request extension for clients that want to pick a specific
  patch profile.
- **Phase 4**: the server-role opcode quartet (for Battle.net-compatible
  chat/realm servers that offload their own login checks to BNLS).

## License

[MIT](LICENSE).
