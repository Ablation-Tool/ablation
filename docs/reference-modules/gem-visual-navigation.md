# Visual Navigation

## Purpose

Visual navigation lets the investigator see the shape of a reverse-engineering session instead of reconstructing it from a long terminal history. GEM provides a tree, breadcrumbs, Rings, and Treemap over the same authoritative event graph.

The views help the human select where to work next. They do not infer analysis coverage, vulnerability severity, or disk consumption from node count.

## Tree and breadcrumbs

The Lab tree preserves parent/child relationships among artifacts, functions, evidence, observations, hypotheses, findings, and notes. It supports stable expansion, text search, status filters, and ancestor retention when a descendant matches.

**Up** moves to the parent of the chart root; **Home** returns to the root artifact. Clickable breadcrumbs provide another way to move through ancestors without losing the current selection. A selected node is shared with the details view, charts, and the CLI's `state.json`.

Empty filters show a reset explanation rather than looking like missing material. Footer status counts apply filters directly, allowing the user to isolate untouched, blocked, partial, or reviewed work.

## Rings

Rings adapts Ubuntu Baobab's concentric-sector presentation to investigation nodes. Each ring represents one level below the chart root. Angular area represents the subtree's node count, not bytes or completed work.

The user can:

- Click a sector to select its real event node.
- Select the center to move to the parent.
- Use arrow keys to navigate the hierarchy.
- Scroll to adjust visible ring depth.

Sectors below the angular or depth limits are not silently treated as analyzed. The interface reports omitted nodes and continued branches explicitly. Colors follow position and depth rather than encoding review status, which remains visible as text.

## Treemap

Treemap lays out nodes as nested rectangles whose area represents subtree node count. It supports click-to-inspect, pagination for large sibling sets, and reuse of actual tile widgets during resize. Labels remain readable where possible, and very small tiles are not presented as if they were fully explored.

The same position/depth palette keeps the chart visually consistent with the Lab's native theme. Selection updates the real session state; it is not a chart-only selection.

## Shared selection and status

Tree, Rings, and Treemap all address the same event IDs. Selecting a node updates `state.json`, so the next agent prompt can use the visual choice without requiring the user to repeat the path or identifier.

Review status is independent of the chart's color geometry. A large sector means a large recorded subtree, not a large amount of verified analysis or a confirmed vulnerability. This distinction is important when a directory has many entries but little actual inspection.

## Typical workflow

1. Start at the root artifact and inspect its top-level entries.
2. Use the tree to expand a promising branch or Rings to see its depth.
3. Use Treemap to compare the relative size of sibling subtrees.
4. Select the desired node and inspect its details or copy a focused CLI prompt.
5. Record new evidence, then let the views refresh from the authoritative event history.

## Implementation map

- `gem-lab/gem/map_view.py`: Treemap geometry, pagination, and selection
- `gem-lab/gem/rings_view.py`: ring geometry, angular limits, depth controls, and keyboard navigation
- `gem-lab/gem/chart_colors.py`: position/depth palette and readable text colors
- `gem-lab/gem/app.py`: Tk tree, details, and filtering
- `gem-lab/gem/gtk_app.py`: GTK tree, breadcrumbs, chart container, and native selection
- `gem-lab/gem/events.py`: authoritative node graph and selection state

## Limits and validation

A directory's top-level inventory does not prove recursive coverage. Chart size is not a confidence score, and omitted small or deep nodes must not be counted as inspected work.

Tests cover ring angles, depth and angular omissions, keyboard and center navigation, pagination, exact allocation, tile reuse, real Cairo rendering, deep trees, large sibling sets, and shared chart selection. Native tests also check that the tree remains beside the chart rather than being replaced by it.
