# Design thesis

This is a field notebook for readers following technical solves. A dark, continuous **route rail** holds the two special challenges and levels 9 through 1 like stops on an investigation path. The cover uses a typographic TISC 26 folio rather than a fabricated event logo. Each report opens onto a quiet reading sheet; evidence media and code retain their place in the narrative.

## Tokens

| Role | Value | Use |
| --- | --- | --- |
| Deep ink | `#18303A` | Route rail, headings |
| Ink | `#243740` | Body copy |
| Paper | `#F7F9F8` | Reading surface |
| Mist | `#EAF0EF` | Supporting panels |
| Rule | `#C4D2D0` | Structural separators |
| Signal blue | `#285D9A` | Links, selected route |
| Amber | `#A24E17` | Small evidence and section markers |

Body and interface: local system sans stack led by Segoe UI. Code: local Cascadia Code or Consolas. The strong, narrow heading treatment uses Bahnschrift where available, with system sans fallback. No network font request.

## Layout

Desktop: a fixed-width left route rail, a flexible document column capped around 76 characters, and a compact contents column on the right for long reports, including both special challenges. Everything aligns left. Mobile: a compact disclosure navigator precedes the report; contents remain in the article flow.

```
┌ route rail ───┬ report heading + prose ──────────┬ contents ┐
│ stop 01       │ evidence, code, tables            │ section  │
│ stop 02       │                                   │ section  │
│ active stop   │                                   │          │
└───────────────┴───────────────────────────────────┴──────────┘
```

## Review against the brief and skill

The route rail communicates the published challenge order, shows the current stop, and stays available while reading. Stars mark the two unnumbered specials; the numbered reports count down from 9. The paper is cool and neutral, and blue denotes controls rather than a neon terminal palette. Section rules, labels, and spacing help navigation; decorative motion is omitted. Wide margins and a single body column keep long technical prose legible, while the embedded viewers resize with their content.
