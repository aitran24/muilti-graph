(() => {
class InspectPanel {
  constructor(elements) {
    this.metaEl = elements.metaEl;
    this.boxEl = elements.boxEl;
    this.copyBtnEl = elements.copyBtnEl;
    this.clearBtnEl = elements.clearBtnEl;
    this.onNotify = typeof elements.onNotify === "function" ? elements.onNotify : null;

    this.currentText = "";
    this._bindEvents();
    this.reset();
  }

  static _toSingleLine(value) {
    return String(value || "")
      .replace(/\s+/g, " ")
      .trim();
  }

  static _formatValue(value) {
    if (value === null || value === undefined) {
      return "";
    }

    if (Array.isArray(value)) {
      return value.map((item) => InspectPanel._toSingleLine(item)).join(", ");
    }

    if (typeof value === "object") {
      return Object.entries(value)
        .map(
          ([key, entryValue]) =>
            `${InspectPanel._toSingleLine(key)}=${InspectPanel._toSingleLine(entryValue)}`
        )
        .join(", ");
    }

    return InspectPanel._toSingleLine(value);
  }

  static _escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  static _toInspectablePairs(payload) {
    const source = payload && typeof payload === "object" ? payload : {};
    const entries = Object.entries(source).filter(([, value]) => {
      if (value === null || value === undefined) {
        return false;
      }
      if (typeof value === "string") {
        return value.trim().length > 0;
      }
      if (Array.isArray(value)) {
        return value.length > 0;
      }
      if (typeof value === "object") {
        return Object.keys(value).length > 0;
      }
      return true;
    });

    if (!entries.length) {
      return [];
    }

    const preferredOrder = [
      "process_name",
      "guid",
      "pid",
      "image_path",
      "command_line",
      "original_file_name",
      "image_hash",
      "command_hash",
      "parent_process_id",
      "user_id",
      "event_id",
      "id",
      "type",
      "entity_class",
      "display_name",
      "name",
    ];

    const rank = new Map(preferredOrder.map((key, index) => [key, index]));
    entries.sort(([leftKey], [rightKey]) => {
      const leftRank = rank.has(leftKey) ? rank.get(leftKey) : Number.MAX_SAFE_INTEGER;
      const rightRank = rank.has(rightKey) ? rank.get(rightKey) : Number.MAX_SAFE_INTEGER;
      if (leftRank !== rightRank) {
        return leftRank - rightRank;
      }
      return leftKey.localeCompare(rightKey);
    });

    return entries;
  }

  static _formatInspectText(payload) {
    const pairs = InspectPanel._toInspectablePairs(payload);
    if (!pairs.length) {
      return "No inspectable properties.";
    }

    return pairs
      .map(([key, value]) => `${key}: ${InspectPanel._formatValue(value)}`)
      .join("\n");
  }

  static _formatInspectHtml(payload) {
    const pairs = InspectPanel._toInspectablePairs(payload);
    if (!pairs.length) {
      return '<div class="inspect-empty">No inspectable properties.</div>';
    }

    return pairs
      .map(([key, value]) => {
        const safeKey = InspectPanel._escapeHtml(key);
        const safeValue = InspectPanel._escapeHtml(InspectPanel._formatValue(value));
        return (
          '<div class="inspect-row">' +
          `<span class="inspect-field">${safeKey}</span>` +
          '<span class="inspect-separator">:</span>' +
          `<span class="inspect-value">${safeValue}</span>` +
          '</div>'
        );
      })
      .join("");
  }

  _bindEvents() {
    if (this.copyBtnEl) {
      this.copyBtnEl.addEventListener("click", async () => {
        await this.copyCurrentInspectText();
      });
    }

    if (this.clearBtnEl) {
      this.clearBtnEl.addEventListener("click", () => {
        this.reset();
      });
    }
  }

  _notify(message, level = "info") {
    if (this.onNotify) {
      this.onNotify(message, level);
    }
  }

  reset(message = "Click a node to inspect properties.") {
    this.currentText = String(message || "");

    if (this.metaEl) {
      this.metaEl.textContent = "No node selected.";
    }

    if (this.boxEl) {
      this.boxEl.textContent = this.currentText;
    }
  }

  render(details) {
    if (!details || !details.node) {
      this.reset();
      return;
    }

    const outgoing = Array.isArray(details.outgoing) ? details.outgoing : [];
    const incoming = Array.isArray(details.incoming) ? details.incoming : [];
    const node = details.node;

    if (this.metaEl) {
      this.metaEl.textContent = [
        `Selected: ${node.label || node.id}`,
        `group=${node.group || "Unknown"}`,
        `outgoing=${outgoing.length}`,
        `incoming=${incoming.length}`,
      ].join(" | ");
    }

    const inspectTarget =
      node && node.properties && Object.keys(node.properties).length
        ? node.properties
        : {
            id: node.id,
            label: node.label,
            type: node.type,
            group: node.group,
          };

    this.currentText = InspectPanel._formatInspectText(inspectTarget);
    if (this.boxEl) {
      this.boxEl.innerHTML = InspectPanel._formatInspectHtml(inspectTarget);
    }
  }

  async copyCurrentInspectText() {
    const text = String(this.currentText || "").trim();
    if (!text) {
      this._notify("Nothing to copy from inspect panel.", "error");
      return;
    }

    try {
      await navigator.clipboard.writeText(text);
      this._notify("Inspect text copied to clipboard.");
    } catch (error) {
      this._notify(`Failed to copy inspect text: ${error.message}`, "error");
    }
  }
}

window.Streamline = window.Streamline || {};
window.Streamline.InspectPanel = InspectPanel;
})();
