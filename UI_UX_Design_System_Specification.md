# UI/UX Design System Specification

**Theme Name:** Enterprise Minimalist (Bootstrap 5)
**Global Vibe:** Clean, professional, academic, and data-focused.
**Core Framework:** HTML5 + Bootstrap 5 (Utility-class driven, no custom CSS)

## 1. Global Canvas & Layout
*   **Background:** Soft light-gray canvas to make white components pop.
    *   *Classes:* `<body class="bg-light">`
*   **Container System:** Responsive centered containers for forms/dashboards, and fluid containers for heavy data admin views.
    *   *Classes:* `container` (standard), `container-fluid px-4` (wide screens), `row`, `col-md-8`, `col-md-4`.
*   **Spacing:** Consistent use of Bootstrap's spacing utilities to ensure breathing room.
    *   *Classes:* `mb-4` (bottom margin for sections), `p-4` or `p-5` (internal padding for standalone forms).

## 2. Navigation
*   **Top Navbar:** High-contrast dark navigation bar anchored at the top.
    *   *Classes:* `<nav class="navbar navbar-dark bg-dark mb-4">`
*   **Brand/Text:** Simple, bold white text for the brand logo/name.

## 3. Cards & Panels
*   **Base Card:** White background with subtle shadows to lift off the light gray canvas.
    *   *Classes:* `card shadow-sm border-0 mb-4`
*   **Categorization Indicators:** Use Bootstrap's border-start utilities to give visual cues to different types of data or statuses (e.g., primary for info, success for active, danger for alerts).
    *   *Classes:* `border-start border-primary border-4`
*   **Card Headers:** Clean, unstyled headers for grouping content.
    *   *Classes:* `card-header bg-white border-bottom-0 pt-4 pb-0`

## 4. Data Display (Tables & Lists)
*   **Tables:** Clean, hoverable tables for dense data presentation. No vertical borders, distinct horizontal dividers.
    *   *Classes:* `table table-hover table-borderless align-middle`
    *   *Headers:* `table-light text-secondary` for subtle table headers.
*   **Lists:** Flush list groups for simple repetitive data that doesn't require a full table structure.
    *   *Classes:* `list-group list-group-flush`

## 5. Forms & Inputs
*   **Form Layout:** Full-width inputs stacked vertically for clarity.
*   **Labels:** Bold labels to clearly demarcate input fields.
    *   *Classes:* `form-label fw-bold`
*   **Inputs:** Standard Bootstrap 5 form controls with subtle focus rings.
    *   *Classes:* `form-control`, `form-select`
*   **Buttons:** Solid primary colors for primary actions, outlined or subtle buttons for secondary actions.
    *   *Classes:* `btn btn-primary w-100` (for main submit), `btn btn-outline-secondary` (for cancel/back).

## 6. Typography & Colors
*   **Headings:** Use default Bootstrap typography (system fonts) but rely on utility classes for hierarchy.
    *   *Classes:* `h4 fw-bold text-dark`, `text-muted` (for subtitles).
*   **Primary Action Color:** Bootstrap standard primary blue (`text-primary`, `bg-primary`, `btn-primary`).
*   **Text Hierarchy:**
    *   Primary Text: `text-dark`
    *   Secondary/Meta Text: `text-muted` or `text-secondary`
    *   Status/Highlights: `text-success`, `text-danger`, `text-warning`

---
*Note: This design system relies entirely on Bootstrap 5 utility classes to ensure a lightweight, maintainable, and highly consistent UI without the need for custom CSS files.*
