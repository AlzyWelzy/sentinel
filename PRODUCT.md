# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Two groups, served equally (owner's answer, 2026-11-20):

- Small hosting and MSP teams running dozens to a few hundred customer servers and the switches, firewalls and Proxmox clusters next to them. Several people per organisation, roles, on-call rotations; often checking an alert from a phone.
- Solo developers and small startups with a handful of servers, who want alerts that work with almost no setup.

The job in both cases: know within minutes when a server, service, check or device stops working, know *what* failed, and confirm it recovered, without being buried in duplicate emails.

## Product Purpose

Sentinel is multi-tenant monitoring for servers, uptime and site networks at sentinel.rajpoot.app. One agent command per server; metrics every 30 s, checks, plugins, logs; rules open incidents with a timeline and notify verified contacts; status pages and PDF reports. Success: a stranger signs up, installs the agent, and gets a useful alert email from Sentinel's own domain, all in Sentinel's own UI.

## Positioning

- Alerts are grouped and blip-suppressed from running a real fleet of ~80 servers behind shared NAT: one email per person per event, held 60 s, skipped when the server is back.
- Every alert says what failed (the plugin, the check, the full mount with space left).
- The same agent polls the site's switches, firewalls and Proxmox over SNMP/API; LLDP topology makes servers depend on their switch automatically, so a dead switch is one alert.
- Works without sudo on customer servers; Linux, BSD, Windows, Docker.

## Operating Context

Operators live in the incident list, server detail and overview during the day, and in email/push alerts at night. Install happens once per server by copying a command. Roles: owner, admin, member, read-only; superadmins run the installation. Public status pages are seen by the operators' own customers. A fleet wall runs on a TV.

## Capabilities and Constraints

- Next.js App Router, TypeScript strict, Tailwind v4, TanStack Query, uPlot, typed client from OpenAPI. Light and dark themes.
- Every existing screen, flow and route stays (the 41-step browser journey, extras, network UI and access matrix in `e2e/` must keep passing).
- Undecided: pricing and billing (nothing built; never show prices).

## Brand Commitments

- Name: Sentinel. Domain sentinel.rajpoot.app. Copy is plain, specific, behaviour-first (as in AGENTS.md and the help page).

## Evidence on Hand

- Real behaviour documented in README.md, ARCHITECTURE.md, AGENTS.md (fleet lessons, live tests).
- No customers, testimonials, logos, benchmarks or uptime figures exist: never invent them.

## Product Principles

1. Say what failed, in words a tired on-call person reads at 3 a.m.
2. One event, one message: fewer, better alerts beat more alerts.
3. Five minutes from sign-up to first server reporting.
4. The same screens work for 3 servers and 300.
5. Customer data on screen is untrusted text: escape it, cut it, never let it break layout.

## Accessibility & Inclusion

WCAG 2.2 AA contrast in both themes; full keyboard use; status never by colour alone; respects reduced motion; usable at phone width.
