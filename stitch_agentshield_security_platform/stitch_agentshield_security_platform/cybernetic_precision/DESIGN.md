---
name: Cybernetic Precision
colors:
  surface: '#faf8ff'
  surface-dim: '#d2d9f4'
  surface-bright: '#faf8ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f2f3ff'
  surface-container: '#eaedff'
  surface-container-high: '#e2e7ff'
  surface-container-highest: '#dae2fd'
  on-surface: '#131b2e'
  on-surface-variant: '#434655'
  inverse-surface: '#283044'
  inverse-on-surface: '#eef0ff'
  outline: '#737686'
  outline-variant: '#c3c6d7'
  surface-tint: '#0053db'
  primary: '#004ac6'
  on-primary: '#ffffff'
  primary-container: '#2563eb'
  on-primary-container: '#eeefff'
  inverse-primary: '#b4c5ff'
  secondary: '#006c4a'
  on-secondary: '#ffffff'
  secondary-container: '#82f5c1'
  on-secondary-container: '#00714e'
  tertiary: '#ae0010'
  on-tertiary: '#ffffff'
  tertiary-container: '#d52022'
  on-tertiary-container: '#ffecea'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#dbe1ff'
  primary-fixed-dim: '#b4c5ff'
  on-primary-fixed: '#00174b'
  on-primary-fixed-variant: '#003ea8'
  secondary-fixed: '#85f8c4'
  secondary-fixed-dim: '#68dba9'
  on-secondary-fixed: '#002114'
  on-secondary-fixed-variant: '#005137'
  tertiary-fixed: '#ffdad6'
  tertiary-fixed-dim: '#ffb4ab'
  on-tertiary-fixed: '#410002'
  on-tertiary-fixed-variant: '#93000b'
  background: '#faf8ff'
  on-background: '#131b2e'
  surface-variant: '#dae2fd'
typography:
  display-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 40px
    fontWeight: '700'
    lineHeight: 48px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Plus Jakarta Sans
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Plus Jakarta Sans
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 20px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 16px
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '700'
    lineHeight: 12px
    letterSpacing: 0.05em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  unit: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 48px
  gutter: 16px
  margin-mobile: 16px
  margin-desktop: 32px
---

## Brand & Style

This design system is engineered for high-stakes security environments where clarity, speed of cognition, and technical rigor are paramount. The aesthetic merges **Corporate Modernism** with **High-Precision Minimalism**, creating a "workstation" feel that prioritizes data density without sacrificing elegance.

The UI evokes an atmosphere of elite technical expertise. It utilizes a "Slate Canvas" methodology—layering subtle tonal shifts to define functional zones. While primarily flat and structural, the system employs **Focused Glassmorphism** specifically for overlays and floating command bars to maintain environmental context. The emotional response is one of controlled authority, reliability, and surgical accuracy.

## Colors

The palette is anchored by a high-contrast foundation to ensure zero-latency readability of security logs and threat vectors.

- **Primary (Electric Blue):** Reserved for action-oriented elements, active states, and primary navigation focus.
- **Success (Emerald):** Indicates validated security states, encrypted traffic, and resolved vulnerabilities.
- **Vulnerability (Crimson):** High-signal color for threats, system breaches, and critical errors.
- **Neutral (Slate Navy):** Used for all primary text and iconography to maintain a professional, high-contrast legibility.
- **Surfaces:** `Pure White` is used for foreground cards and active work areas, while `Slate Canvas` provides the structural background to reduce eye strain during extended monitoring sessions.

## Typography

The typographic hierarchy distinguishes between **Executive Summary** (Plus Jakarta Sans) and **Operational Data** (Inter/JetBrains Mono).

- **Plus Jakarta Sans:** Used for headlines and page titles to provide a modern, approachable entry point to complex data.
- **Inter:** The primary workhorse for UI labels, form fields, and descriptive text, chosen for its exceptional clarity at small sizes.
- **JetBrains Mono:** Strictly enforced for logs, terminal outputs, IP addresses, and hash values. This font signals "raw data" to the engineer and ensures character alignment in complex security strings.

## Layout & Spacing

The design system utilizes a **12-column rigid grid** for dashboard layouts, transitioning to a specialized **side-panel / main-stage** model for the engineer's workstation. 

- **Layout Model:** The "Workstation" layout features a fixed 280px left navigation and a collapsible 320px right inspection panel. The central "Stage" is fluid.
- **Rhythm:** An 8px linear scale (Soft Grid) governs all components, but a 4px micro-increment is permitted for dense data tables and code editors to maximize information density.
- **Adaptation:** On tablet, the inspection panel becomes a bottom sheet. On mobile, the interface collapses to a single-column list of security events, prioritizing the "Vulnerability" (Crimson) signals.

## Elevation & Depth

Hierarchy is established primarily through **Tonal Layering** rather than heavy shadows to maintain a "flat-technical" feel.

- **Level 0 (Canvas):** `#F8FAFC` — The base layer for the application frame.
- **Level 1 (Surface):** `#FFFFFF` — Cards, main content areas, and input fields. Defined by a 1px border (`#E2E8F0`).
- **Level 2 (Active/Hover):** Subtle 2px "Soft Smoke" shadows (`rgba(15, 23, 42, 0.05)`) are used only when an element is interactive or elevated (e.g., a dragged log entry).
- **Glassmorphism:** Reserved for Modal Backdrops and Global Search. Use a `backdrop-filter: blur(8px)` with a `#FFFFFF80` (50% white) tint to maintain technical focus on the underlying data.

## Shapes

The "Round Eight" philosophy ensures the interface feels modern but disciplined. 

- **Components:** Standard buttons, input fields, and cards utilize a `0.5rem` (8px) radius.
- **System Tags/Chips:** Use `rounded-lg` (1rem) for status indicators to contrast against the more rigid square-ish layout.
- **Code Blocks:** Use a tighter `0.25rem` (4px) radius to emphasize their technical, "embedded" nature.

## Components

- **Buttons:** Primary buttons use a solid Electric Blue fill with white Inter Medium text. Secondary buttons use a Slate Navy outline. All buttons have a high-contrast focus ring of 2px.
- **Security Chips:** Status indicators (Safe, Warning, Critical) use a "Light-on-Dark" or "Tinted-Background" style. E.g., a "Critical" chip uses a light crimson background with deep crimson text in JetBrains Mono.
- **Data Tables:** High-density rows with 1px bottom borders. Hovering over a row changes the background to a subtle Slate Canvas tint.
- **Input Fields:** Pure White background with a 1px Slate border. On focus, the border transitions to Electric Blue with a subtle 2px glow.
- **Log Viewer:** A specialized component using JetBrains Mono, a Slate Navy background, and syntax highlighting for JSON/System logs.
- **Command Palette:** A centered, glassmorphic search bar that appears on `Cmd+K`, providing instant access to agent tools and security scripts.