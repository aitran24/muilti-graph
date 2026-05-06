(() => {
function normalizeFilters(filters) {
  const seen = new Set();
  const normalized = [];

  (filters || []).forEach((raw) => {
    const value = String(raw || "").trim();
    if (!value) {
      return;
    }

    const dedupeKey = value.toLowerCase();
    if (seen.has(dedupeKey)) {
      return;
    }

    seen.add(dedupeKey);
    normalized.push(value);
  });

  return normalized;
}

class RelationFilterPanel {
  constructor(elements) {
    this.inputEl = elements.inputEl;
    this.addBtnEl = elements.addBtnEl;
    this.listEl = elements.listEl;
    this.clearBtnEl = elements.clearBtnEl;
    this.suggestionsEl = elements.suggestionsEl;

    this.filters = [];
    this.suggestions = [];
    this.onChange = null;

    this._bindEvents();
    this._renderFilters();
    this._renderSuggestions();
  }

  _bindEvents() {
    if (this.addBtnEl) {
      this.addBtnEl.addEventListener("click", () => {
        this.addFilter(this.inputEl ? this.inputEl.value : "");
      });
    }

    if (this.inputEl) {
      this.inputEl.addEventListener("keydown", (event) => {
        if (event.key !== "Enter") {
          return;
        }
        event.preventDefault();
        this.addFilter(this.inputEl.value);
      });
    }

    if (this.listEl) {
      this.listEl.addEventListener("click", (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) {
          return;
        }
        if (!target.classList.contains("remove-pattern")) {
          return;
        }

        const index = Number.parseInt(String(target.dataset.index || ""), 10);
        if (!Number.isInteger(index)) {
          return;
        }
        this.removeFilter(index);
      });
    }

    if (this.clearBtnEl) {
      this.clearBtnEl.addEventListener("click", () => {
        this.clearFilters();
      });
    }

    if (this.suggestionsEl) {
      this.suggestionsEl.addEventListener("click", (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) {
          return;
        }

        const button = target.closest("button.relation-chip");
        if (!button) {
          return;
        }

        const relation = String(button.dataset.relation || "").trim();
        if (!relation) {
          return;
        }

        this.toggleFilter(relation);
      });
    }
  }

  setOnChange(callback) {
    this.onChange = typeof callback === "function" ? callback : null;
  }

  getFilters() {
    return [...this.filters];
  }

  setFilters(filters, emitChange = true) {
    this.filters = normalizeFilters(filters);
    this._renderFilters();
    this._renderSuggestions();

    if (emitChange && this.onChange) {
      this.onChange(this.getFilters());
    }
  }

  setSuggestions(relationCountMap) {
    const entries = Object.entries(relationCountMap || {})
      .map(([relation, count]) => ({ relation, count: Number(count) || 0 }))
      .filter((item) => item.relation)
      .sort((a, b) => {
        if (b.count !== a.count) {
          return b.count - a.count;
        }
        return a.relation.localeCompare(b.relation);
      });

    this.suggestions = entries;
    this._renderSuggestions();
  }

  addFilter(value) {
    const normalized = normalizeFilters([value]);
    if (!normalized.length) {
      return;
    }

    const next = normalizeFilters([...this.filters, normalized[0]]);
    const changed = next.length !== this.filters.length;
    this.filters = next;

    if (this.inputEl) {
      this.inputEl.value = "";
      this.inputEl.focus();
    }

    this._renderFilters();
    this._renderSuggestions();

    if (changed && this.onChange) {
      this.onChange(this.getFilters());
    }
  }

  removeFilter(index) {
    if (index < 0 || index >= this.filters.length) {
      return;
    }

    this.filters.splice(index, 1);
    this._renderFilters();
    this._renderSuggestions();

    if (this.onChange) {
      this.onChange(this.getFilters());
    }
  }

  toggleFilter(value) {
    const relation = String(value || "").trim();
    if (!relation) {
      return;
    }

    const existingIndex = this.filters.findIndex(
      (item) => item.toLowerCase() === relation.toLowerCase()
    );

    if (existingIndex >= 0) {
      this.removeFilter(existingIndex);
      return;
    }

    this.addFilter(relation);
  }

  clearFilters() {
    if (!this.filters.length) {
      return;
    }

    this.filters = [];
    this._renderFilters();
    this._renderSuggestions();

    if (this.onChange) {
      this.onChange(this.getFilters());
    }
  }

  _renderFilters() {
    if (!this.listEl) {
      return;
    }

    this.listEl.innerHTML = "";

    if (!this.filters.length) {
      const empty = document.createElement("li");
      empty.className = "empty";
      empty.textContent = "No relation filter.";
      this.listEl.appendChild(empty);

      if (this.clearBtnEl) {
        this.clearBtnEl.disabled = true;
      }
      return;
    }

    this.filters.forEach((filter, index) => {
      const row = document.createElement("li");
      row.className = "pattern-item";

      const code = document.createElement("code");
      code.textContent = filter;

      const removeButton = document.createElement("button");
      removeButton.type = "button";
      removeButton.className = "remove-pattern";
      removeButton.dataset.index = String(index);
      removeButton.textContent = "Remove";

      row.appendChild(code);
      row.appendChild(removeButton);
      this.listEl.appendChild(row);
    });

    if (this.clearBtnEl) {
      this.clearBtnEl.disabled = false;
    }
  }

  _renderSuggestions() {
    if (!this.suggestionsEl) {
      return;
    }

    this.suggestionsEl.innerHTML = "";

    if (!this.suggestions.length) {
      const empty = document.createElement("span");
      empty.className = "empty";
      empty.textContent = "No relation observed yet.";
      this.suggestionsEl.appendChild(empty);
      return;
    }

    this.suggestions.forEach((item) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "relation-chip";
      button.dataset.relation = item.relation;
      button.textContent = `${item.relation} (${item.count})`;

      const active = this.filters.some(
        (filter) => filter.toLowerCase() === item.relation.toLowerCase()
      );
      button.classList.toggle("active", active);

      this.suggestionsEl.appendChild(button);
    });
  }
}

window.Streamline = window.Streamline || {};
window.Streamline.RelationFilterPanel = RelationFilterPanel;
})();
