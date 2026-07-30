/**
 * Shared Recharts styling configuration.
 * Import these helpers in any chart component for consistent styling.
 */

export const CHART_TOOLTIP_STYLE = {
  backgroundColor: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: "8px",
  boxShadow: "0 4px 12px rgba(0, 0, 0, 0.3)",
  fontSize: 12,
  color: "hsl(var(--foreground))",
} as const;

export const CHART_TOOLTIP_LABEL_STYLE = {
  color: "hsl(var(--foreground))",
  fontWeight: 600,
  marginBottom: "8px",
} as const;

export const CHART_TOOLTIP_ITEM_STYLE = {
  color: "hsl(var(--muted-foreground))",
  fontSize: "13px",
} as const;

export const CHART_CURSOR = { fill: "hsl(var(--accent))", opacity: 0.1 } as const;

export const CHART_AXIS_TICK = {
  fill: "hsl(var(--muted-foreground))",
  fontSize: 11,
} as const;

export const CHART_GRID = {
  strokeDasharray: "3 3",
  stroke: "hsl(var(--border))",
  opacity: 0.3,
} as const;

export const CHART_LEGEND_STYLE = { fontSize: 11 } as const;

/** Standard animation durations */
export const CHART_ANIM = {
  barDuration: 800,
  barEasing: "ease-out" as const,
  lineDuration: 1000,
  lineEasing: "ease-out" as const,
  pieDuration: 800,
  pieEasing: "ease-out" as const,
};
