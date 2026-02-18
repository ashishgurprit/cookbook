# Data Visualization Chart Selection Guide

## Core Principle

> "The greatest value of a picture is when it forces us to notice what we never expected to see." — John Tukey

**Golden Rule:** Choose chart type based on the data relationship you're revealing, not what "looks cool."

## Chart Selection Decision Tree

```
What do you want to show?

├─ COMPARISON (Comparing values)
│  ├─ Between categories? → BAR CHART
│  ├─ Over time (few data points)? → COLUMN CHART
│  ├─ Many categories? → HORIZONTAL BAR CHART
│  └─ Against a target? → BULLET CHART
│
├─ DISTRIBUTION (How data is spread)
│  ├─ Single variable? → HISTOGRAM
│  ├─ Multiple groups? → BOX PLOT, VIOLIN PLOT
│  ├─ Over time? → RIDGELINE PLOT
│  └─ Two variables? → SCATTER PLOT
│
├─ COMPOSITION (Part-to-whole relationships)
│  ├─ Static snapshot? → PIE CHART (≤5 slices), DONUT CHART
│  ├─ Over time? → STACKED AREA CHART, STACKED BAR
│  ├─ Hierarchical? → TREEMAP, SUNBURST
│  └─ Relative %? → 100% STACKED BAR
│
├─ RELATIONSHIP (Correlation between variables)
│  ├─ Two variables? → SCATTER PLOT
│  ├─ Three variables? → BUBBLE CHART
│  ├─ Network/connections? → NETWORK DIAGRAM
│  └─ Cause and effect? → SANKEY DIAGRAM
│
└─ CHANGE OVER TIME (Trends, patterns)
   ├─ Single metric? → LINE CHART
   ├─ Multiple metrics? → MULTI-LINE CHART
   ├─ Cyclical pattern? → CIRCULAR/RADIAL CHART
   └─ Range/uncertainty? → LINE CHART + CONFIDENCE BANDS
```

---

## Chart Types Deep Dive

### 1. Bar Chart (Horizontal or Vertical)

**Purpose:** Compare values across categories

```
Sales by Region:

North ████████████████ 150
South ████████████ 120
East  ██████████████████ 180
West  ████████ 80
      0   50  100  150  200
```

**When to Use:**
- Comparing discrete categories
- Ranking (sort by value for easy reading)
- Negative and positive values (bars extend both directions)

**Best Practices:**
- Start Y-axis at 0 (never truncate for bar charts)
- Sort by value (descending) unless order matters (time, geography)
- Horizontal bars for long category names
- Limit to 10-15 categories (more = table, not chart)

**Avoid:**
- 3D bars (distorts perception)
- Too many colors (use one color + highlight accent)
- Decorative icons inside bars (chartjunk)

---

### 2. Line Chart

**Purpose:** Show trends over continuous time

```
Website Traffic (2023-2024):

8k │         ╱‾‾╲
   │       ╱     ╲     ╱‾╲
6k │     ╱         ╲ ╱   ╲
   │   ╱             ╲     ╲
4k │ ╱                 ╲___  ╲
   └─────────────────────────
   Jan  Apr  Jul  Oct  Jan  Apr
```

**When to Use:**
- Time series data (days, months, years)
- Continuous data (not discrete categories)
- Showing trends, patterns, cycles

**Best Practices:**
- Smooth lines for continuous data, points + lines for discrete
- Max 5 lines (more = spaghetti chart, use small multiples instead)
- Direct labeling (label lines, not legend)
- Y-axis can start above 0 IF context is clear

**Avoid:**
- Connecting unrelated data points (categorical data)
- Too many lines crossing (use area chart or small multiples)
- Dual Y-axes (confusing, better to normalize or use separate charts)

---

### 3. Scatter Plot

**Purpose:** Show correlation/relationship between two variables

```
Height vs Weight:

Weight
  │     ●
200│   ●  ●●
  │  ●● ●  ●
150│ ●  ●● ●
  │●● ●  ●
100│● ●
  └───────────
   150  175  200
      Height (cm)
```

**When to Use:**
- Correlation between two continuous variables
- Identifying outliers
- Pattern detection (clusters, trends)

**Best Practices:**
- Add trendline if correlation is meaningful
- Use bubble chart (size = 3rd variable) for three dimensions
- Color code by category (e.g., male/female, regions)
- Show R² value if relevant (correlation strength)

**Avoid:**
- Connecting points with lines (unless time series)
- Overplotting (too many points = use density plot or hexbin)
- Forcing correlation where none exists

---

### 4. Pie Chart

**Purpose:** Part-to-whole relationships (controversial, use sparingly)

```
Market Share:

     ┌─────┐
   ╱   A   ╲
  │   40%   │
  │    B    │
  │   25%   │
  │  C      │
  │  20%    │
  │ D 15%   │
  └─────────┘
```

**When to Use:**
- Maximum 5 slices (ideally 2-3)
- Values sum to 100%
- Part-to-whole is the ONLY message

**Best Practices:**
- Start at 12 o'clock, order by size (largest first, clockwise)
- Show percentages directly on slices
- Use donut chart for modern look (easier to compare arc lengths)

**Avoid:**
- More than 5 slices (use bar chart instead)
- 3D pie charts (distorts perception)
- Exploded slices (gimmicky, hard to read)
- Multiple pie charts for comparison (use 100% stacked bar instead)

**Alternatives:**
- **Bar chart:** Easier to compare values precisely
- **Waffle chart:** 100 squares, each = 1%
- **Treemap:** Hierarchical part-to-whole

---

### 5. Stacked Bar/Area Chart

**Purpose:** Part-to-whole composition over time or categories

```
Revenue by Product (Stacked Area):

$M
80│         ╱Product C
  │       ╱╱╱╱╱╱╱╱
60│     ╱╱Product B
  │   ╱╱╱╱╱╱╱╱
40│ ╱╱Product A
  │╱╱╱╱╱╱╱╱
20│╱╱╱╱╱
  └────────────────
  Q1 Q2 Q3 Q4 Q1 Q2
```

**When to Use:**
- Showing total + composition simultaneously
- Change in composition over time
- Emphasis on total (stacked area) or categories (stacked bar)

**Best Practices:**
- Order by importance (most important on bottom for area, top for bar)
- Max 5-7 segments (more = hard to read)
- Use consistent colors across charts
- 100% stacked for relative proportions (not absolute)

**Avoid:**
- Comparing non-adjacent segments (hard to see changes)
- Too many segments (use grouped bar or line chart)
- Negative values (use diverging stacked bar)

---

### 6. Box Plot (Box-and-Whisker)

**Purpose:** Show distribution, median, quartiles, outliers

```
Test Scores by Class:

100│      ●
   │      │
 75│   ┌──┼──┐
   │   │  │  │ ◄─ Median
 50│   │  │  │
   │   └──┼──┘
 25│      │
   │   ●  │
  0└──────┴──────
    Class A  Class B
```

**When to Use:**
- Comparing distributions across groups
- Identifying outliers
- Showing spread (variability)

**Components:**
- **Box:** Interquartile range (25th to 75th percentile)
- **Line in box:** Median (50th percentile)
- **Whiskers:** Extend to 1.5× IQR or min/max
- **Dots:** Outliers beyond whiskers

**Best Practices:**
- Show individual data points if <20 values (overlaid on box)
- Use violin plot for better shape visualization
- Horizontal for many groups

**Avoid:**
- Small sample sizes (<10, show raw points instead)
- When distribution shape matters more than summary (use histogram)

---

### 7. Histogram

**Purpose:** Show distribution of continuous data

```
Age Distribution:

Freq
30│     ██
  │     ██
20│  ██ ██ ██
  │  ██ ██ ██
10│  ██ ██ ██ ██
  │  ██ ██ ██ ██
 0└─────────────
   20 30 40 50 60
      Age (years)
```

**When to Use:**
- Showing frequency distribution
- Identifying skewness, outliers, patterns
- Understanding data shape (normal, bimodal, etc.)

**Best Practices:**
- Choose bin width carefully (5-20 bins typical, use Sturges' rule)
- Show density curve overlay for smooth distribution
- Label axes clearly (frequency or %)

**Avoid:**
- Too few bins (loses detail) or too many (noisy)
- Confusing with bar chart (histogram = continuous, bar = categorical)

---

### 8. Heatmap

**Purpose:** Show patterns in matrix data (3 dimensions: X, Y, Color)

```
Sales by Day & Hour:

Hour    Mon Tue Wed Thu Fri
9am     🟦  🟦  🟦  🟦  🟩
12pm    🟩  🟩  🟨  🟨  🟨
3pm     🟨  🟨  🟨  🟧  🟧
6pm     🟧  🟧  🟧  🟥  🟥
        Low ───────────► High
```

**When to Use:**
- Matrix data (2 categorical axes, 1 numerical value)
- Finding patterns over time + category
- Correlation matrices

**Best Practices:**
- Use sequential color scale (light → dark for single direction)
- Use diverging scale (blue ← white → red for negative/positive)
- Show values in cells if space allows
- Cluster/sort rows and columns for pattern discovery

**Avoid:**
- Rainbow color scales (not perceptually uniform, avoid)
- Too many cells (max ~100×100, otherwise aggregate)

---

### 9. Treemap

**Purpose:** Hierarchical part-to-whole with nested rectangles

```
Tech Company Valuation:

┌────────────────────────────┐
│ Apple                      │
│ $2.5T                      │
├─────────────┬──────────────┤
│ Microsoft   │ Google       │
│ $2.0T       │ $1.5T        │
├──────┬──────┴──────┬───────┤
│Amazon│Tesla │Meta  │NVIDIA │
│$1.2T │$800B │$700B │$600B  │
└──────┴──────┴──────┴───────┘
```

**When to Use:**
- Hierarchical data (categories with subcategories)
- Space-efficient part-to-whole
- Many categories (more than pie chart can handle)

**Best Practices:**
- Use color for additional dimension (category, growth rate)
- Show both label and value
- Sort by size for clarity

**Avoid:**
- Comparing precise values (hard to judge area)
- Deep hierarchies (>3 levels, use sunburst)
- Small rectangles (text becomes unreadable)

---

### 10. Sankey Diagram

**Purpose:** Show flow between stages/categories

```
Website Traffic Flow:

Homepage ─────────60%───────→ Product
   │                           │
   30%                        50%
   │                           ↓
   └──────→ Blog ─────────→ Checkout
            │          20%
           40%
            ↓
          Exit
```

**When to Use:**
- Flow/movement between stages (user journeys, budgets, energy)
- Visualizing transfers and losses
- Multi-stage processes

**Best Practices:**
- Width of flow = magnitude (preserve proportions)
- Left-to-right or top-to-bottom flow
- Label all nodes and major flows

**Avoid:**
- Too many nodes (>15, becomes spaghetti)
- Circular flows (use chord diagram)

---

## Chart Selection by Use Case

### Business Dashboards

**KPI Summary:** Big Numbers (single metric cards)
**Sales Performance:** Bar chart (by region), Line chart (over time)
**Customer Segments:** Pie/Donut (if <5 segments) or Treemap
**Funnel:** Funnel chart or Sankey diagram

### Scientific Papers

**Distributions:** Histogram, Box plot, Violin plot
**Correlations:** Scatter plot with regression line
**Comparisons:** Bar chart with error bars
**Time series:** Line chart with confidence bands

### Marketing Reports

**Campaign Performance:** Grouped bar chart (compare channels)
**Engagement Over Time:** Area chart (stacked for channels)
**Demographics:** Horizontal bar chart, Waffle chart
**Conversion Funnel:** Funnel chart (show drop-off)

### Financial Reports

**Stock Prices:** Candlestick chart (OHLC data)
**Portfolio Composition:** Treemap (hierarchical assets)
**Performance vs Benchmark:** Dual-axis line (use sparingly!)
**Risk/Return:** Scatter plot (risk = X, return = Y)

---

## Advanced Chart Types

### Ridgeline Plot (Joy Plot)
**Purpose:** Distribution changes over time (temperature by month, music genres by era)

### Chord Diagram
**Purpose:** Bidirectional flows between entities (trade between countries, migrations)

### Network Graph
**Purpose:** Relationships/connections (social networks, knowledge graphs)

### Gantt Chart
**Purpose:** Project timelines (task scheduling, resource allocation)

### Waterfall Chart
**Purpose:** Cumulative effect (budget breakdown, profit/loss bridge)

### Bullet Chart
**Purpose:** Performance vs target (KPI dashboards, gauge alternative)

### Small Multiples (Trellis Charts)
**Purpose:** Compare same chart type across categories (sales by region × time)

---

## Color Best Practices for Charts

### Sequential (Low to High)
```
Light Blue → Dark Blue (single hue)
White → Red (intensity increases)
```
**Use:** Heatmaps, choropleth maps, single metric gradient

### Diverging (Negative to Positive)
```
Red ← White → Blue
Bad ← Neutral → Good
```
**Use:** Profit/loss, above/below average, sentiment

### Categorical (Distinct Groups)
```
Blue, Orange, Green, Red, Purple
(Use colorblind-safe palettes)
```
**Use:** Multiple lines, grouped bars, pie slices

### Highlight
```
Gray, Gray, Gray, Orange, Gray
(All muted except one accent)
```
**Use:** Drawing attention to specific data point

**Avoid:**
- ❌ Rainbow scales (not perceptually uniform)
- ❌ Red/green only (colorblind issue, use blue/orange)
- ❌ Too many colors (max 5-7 for categorical)

---

## Accessibility Checklist

- [ ] **Color blind safe:** Test with Color Oracle or Coblis simulator
- [ ] **Contrast:** WCAG AA (4.5:1 text, 3:1 graphics)
- [ ] **Patterns:** Use patterns/textures in addition to color
- [ ] **Labels:** Direct labels, not just legend
- [ ] **Alt text:** Describe chart for screen readers
- [ ] **Data table:** Provide raw data as alternative

---

## Tools & Resources

**Charting Libraries:**
- D3.js (Web, maximum flexibility)
- Chart.js (Web, simple and fast)
- Plotly (Python/R/JS, interactive)
- Matplotlib/Seaborn (Python, publication-quality)
- ggplot2 (R, grammar of graphics)

**Design Tools:**
- Figma (static mockups, design systems)
- Tableau (business intelligence, interactive dashboards)
- Observable (JavaScript notebooks, D3 playground)
- Datawrapper (quick embeddable charts, journalists)
- Flourish (templates, storytelling)

**Learning Resources:**
- *The Visual Display of Quantitative Information* by Edward Tufte
- *Storytelling with Data* by Cole Nussbaumer Knaflic
- [Data-to-Viz](https://www.data-to-viz.com/) - Chart selection tool
- [Flowing Data](https://flowingdata.com/) - Visualization blog (Nathan Yau)
- [Information is Beautiful](https://informationisbeautiful.net/) - Award-winning infographics

---

**Remember:** The best chart is the one that makes the insight immediately obvious. If your audience has to work hard to understand it, choose a simpler chart type or simplify your data.
