# Game Vault

The vault sat behind an entire game, but winning the game was only the first lock. A stale enemy marker produced an accepted 88-action victory replay; a hidden console then led through employee accounts to a production 2FA test code.

## Win the replay

The client opens a fresh TCP connection for each request. Every packet begins with an eight-byte random preamble that seeds a four-word XOR stream; the ordered pair of session IDs binds requests together. A successful handshake returns session IDs, a map seed, an attestation challenge, and a resource key. Resource and replay requests include a deterministic 90-byte client attestation, so the solver reimplements that client function rather than searching for a secret.

Replay actions are little-endian `u32`s encrypted byte by byte. Starting with `r = map_seed` and `delta = XOR(all 16 session-ID bytes)` (or `0x7a` when zero):

```text
c[i] = p[i] XOR ((r + i) & 0xff)
r    = ((r XOR p[i]) + delta) & 0xffffffff
```

The replay checksum is DJB2 over the session pair, action count, and ciphertext. The map also changes each session: MT19937 seeded by `map_seed` performs 100 swaps for each of 64 visits, so `solve.py` rebuilds each permutation before choosing a world entry.

The actual game bug is simpler than this transport. Enemies cycle through a four-slot ring. Enemy1 sets a marker byte, but a later clone fails to clear it reliably. Reuse that slot for a weak enemy, kill it, and the 88-action route earns:

```text
You have received the key!
```

World-map selector `209` opens a developer console without adding a normal replay action.

## Follow the console breadcrumbs

`help` reveals `login`, `chat`, `hints`, and `credits`. A decoded hint points toward the secret shop and four rests used by the replay. `credits` exposes XOR-obfuscated employee labels; `chat` includes the reminder that employees should change default passwords. Testing likely credentials with `check_console_logins.py` finds Sarah Chen's `password123`.

From there the challenge becomes a deliberately silly office escalation chain:

```text
login sarah.chen password123
lookup devon.park
lookup priya.nandakumar
lookup elena.vasquez

login devon.park bubbletea
manual                         # reveals reset_passwrd

login priya.nandakumar elena.vasquez
reset_passwrd adrian.osei chosenpassword
login adrian.osei chosenpassword
source_list
source_dump sentinel_auth.cpp
```

The dumped `sentinel_auth.cpp` contains an unfinished production 2FA check with a hardcoded test code, `125721`. Use Priya's unrestricted reset again for vault administrator Marcus Webb, then submit it:

```text
login priya.nandakumar elena.vasquez
reset_passwrd marcus.webb chosenpassword
login marcus.webb chosenpassword
vault 125721
```

```text
TISC{wh@t_rE_m0r3_Lyk3_LLM_ctf}
```

## Reproduce it

`solve.py` contains the packet stream, attestation, seeded map route, and console chain. `check_console_logins.py` covers the credential search. The precise packet format matters when writing a new harness: the successful handshake is an unframed 37-byte record, while most other replies use `u32_le length | body` framing.
