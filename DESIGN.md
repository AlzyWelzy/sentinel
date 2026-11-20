# Design

Sentinel's visual world is **Panel Schedule**: the fleet as a labelled electrical distribution panel. Every server is a numbered circuit; a failure is a tripped breaker with its reason typed beside it. Tokens live in `web/src/app/globals.css`; components in `web/src/components/ui.tsx`.

## Materials

- **Enamel ground:** cool grey powder coat in light (`--bg #dfe1dc`, panels `#f3f4f1`), charcoal at night (`--bg #121416`, panels `#1a1d20`). No gradients, glass, glow or decorative grids.
- **Nameplates** (`.plate`): an ink plate with engraved light condensed caps. Used for primary buttons, the active nav item, code/command blocks and the closing band. It inverts in dark mode.
- **Directory card:** tables and lists are ruled rows (1px `--line`), condensed caps headers, mono figures. Rules are the containers. Cards are flat, 1px border, 3px corners, no shadow beyond a 1px pressed-steel highlight.

## Type

- Body: **Barlow** (`--font-sans`).
- Nameplates, headings, table headers, badges: **Barlow Condensed** (`font-plate`), caps with 0.04–0.14em tracking. Page titles use it in their own case, because titles often hold hostnames and organisation names, which must show exactly as written.
- Data and measurements: **JetBrains Mono** (`font-mono`, `.tabular` = tabular, slashed zero). Never mono as decoration.

## Colour

Restrained: neutrals plus one fixed severity ramp, used the same way everywhere.

| Role | Light | Dark |
|---|---|---|
| energized / ok | `#1a6b3d` | `#4cc17f` |
| warning | `#855600` | `#e8ad35` |
| tripped / bad | `#b0330f` | `#ff7448` |
| idle / off | `#7d8286` | `#7c8386` |
| links, focus, maintenance (`brand`) | `#1d4f91` | `#8fb4ec` |
| text on a solid status fill (`on-status`) | `#ffffff` | `#121416` |

All text pairs meet WCAG AA (≥4.5:1) on `bg`, `panel` and `panel-2`. Status never relies on colour alone: badges carry the word, breakers carry handle position.

Chart series use cable colours (`chart.tsx`), kept apart from the severity ramp.

## Components

- `Breaker`: the handle up and dark when energized, thrown down in trip orange when tripped, amber for warning, grey when off. Used on the overview panel and the landing example.
- `Badge`: square tag, condensed caps; the tripped badge is a solid fill.
- `Dot`: a small vertical lamp; a tripped lamp blinks in two steps.
- `Meter`: bar meter with tick marks every 10%; the reading turns amber/orange with the bar.
- `PageHeader`: title over a 2px ink rule.
- `Empty`: a drawn breaker, condensed caps title.

## Motion

Crisp and rare: `--ease-out: cubic-bezier(0.23, 1, 0.32, 1)`, 150–240ms.
- Press: `scale(0.97)` on buttons and plate links.
- The signature: a breaker flip (160ms). The landing panel trips one circuit 1.6s after load, types the reason, then feeds the alert slip.
- Mobile menu slides in like a panel door (`.drawer`, `@starting-style`).
- No entrance animation on repeat screens; reduced motion is honoured globally.

## Don't

Gradient text, glow shadows, pill shapes, floating KPI card grids as page structure, eyebrow labels above headings, or uppercase on customer data (hostnames, org names, log lines).
