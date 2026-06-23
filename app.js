(function () {
  'use strict';

  var state = {
    beforeParse: null,
    afterParse: null,
    diff: null,
    filters: {
      vrf: 'all',
      type: 'non-unchanged',
      protocol: 'all',
      prefix: '',
      nextHop: '',
      iface: ''
    }
  };

  var SAMPLE_BEFORE =     'show ip route vrf all\n' +
    'Routing Table: global\n' +
    'Gateway of last resort is 192.0.2.254 to network 0.0.0.0\n' +
    'S*   0.0.0.0/0 [1/0] via 192.0.2.254\n' +
    'C    192.0.2.0/24 is directly connected, Vlan10\n' +
    'L    192.0.2.1/32 is directly connected, Vlan10\n' +
    'O    198.51.100.0/24 [110/20] via 192.0.2.1, 00:01:23, Vlan10\n' +
    'O    198.51.100.128/25 [110/20] via 192.0.2.1, 00:01:23, Vlan10\n' +
    '                     [110/20] via 192.0.2.2, 00:01:23, Vlan20\n' +
    'Routing Table: CUSTOMER_A\n' +
    'O IA 203.0.113.0/24 [110/30] via 198.51.100.1, 00:02:10, Vlan30\n' +
    'B    203.0.113.128/25 [20/0] via 203.0.113.1, 00:10:00\n' +
    'Routing Table: CUSTOMER_B\n' +
    'S    198.51.100.64/26 [1/0] via 198.51.100.254\n';

  var SAMPLE_AFTER =     'show ip route vrf all\n' +
    'Routing Table: global\n' +
    'S*   0.0.0.0/0 [1/0] via 192.0.2.253\n' +
    'C    192.0.2.0/24 is directly connected, Vlan10\n' +
    'L    192.0.2.1/32 is directly connected, Vlan10\n' +
    'O    198.51.100.0/24 [110/30] via 192.0.2.1, 00:09:23, Vlan10\n' +
    'O    198.51.100.128/25 [110/20] via 192.0.2.2, 00:11:23, Vlan20\n' +
    '                     [110/20] via 192.0.2.3, 00:11:23, Vlan30\n' +
    'O E2 203.0.113.64/26 [110/20] via 192.0.2.3, 00:05:00, Vlan30\n' +
    'Routing Table: CUSTOMER_A\n' +
    'O IA 203.0.113.0/24 [110/30] via 198.51.100.1, 4d12h, Vlan30\n' +
    'Routing Table: CUSTOMER_B\n' +
    'S    198.51.100.64/26 [1/0] via 198.51.100.254\n' +
    'S    198.51.100.192/26 [1/0] via 198.51.100.253\n';

  function $(id) {
    return document.getElementById(id);
  }

  function escapeHtml(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function titleCase(value) {
    return String(value || '').charAt(0).toUpperCase() + String(value || '').slice(1);
  }

  function routeText(route) {
    return window.RouteDiffParser.formatRoute(route);
  }

  function pathsText(paths) {
    if (!paths || !paths.length) return '-';
    return paths.map(window.RouteDiffParser.formatPath).join('; ');
  }

  function parseAndDiff() {
    state.beforeParse = window.RouteDiffParser.parse($('beforeInput').value);
    state.afterParse = window.RouteDiffParser.parse($('afterInput').value);
    state.diff = window.RouteDiff.compare(
      state.beforeParse.routes,
      state.afterParse.routes,
      state.beforeParse.warnings.map(function (w) { w.side = 'Before'; return w; }),
      state.afterParse.warnings.map(function (w) { w.side = 'After'; return w; })
    );
    hydrateFilters();
    render();
    $('resultsPanel').hidden = false;
    $('resultsPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function hydrateSelect(select, values, allLabel) {
    var current = select.value || 'all';
    select.innerHTML = '<option value="all">' + escapeHtml(allLabel) + '</option>' + values.map(function (value) {
      return '<option value="' + escapeHtml(value) + '">' + escapeHtml(value) + '</option>';
    }).join('');
    select.value = values.indexOf(current) >= 0 ? current : 'all';
  }

  function hydrateFilters() {
    hydrateSelect($('filterVrf'), state.diff.vrfs, 'All VRFs');
    hydrateSelect($('filterProtocol'), state.diff.protocols, 'All protocols');
  }

  function readFilters() {
    state.filters = {
      vrf: $('filterVrf').value,
      type: $('filterType').value,
      protocol: $('filterProtocol').value,
      prefix: $('filterPrefix').value.trim().toLowerCase(),
      nextHop: $('filterNextHop').value.trim().toLowerCase(),
      iface: $('filterInterface').value.trim().toLowerCase()
    };
  }

  function matchesRouteSearch(item, key, needle) {
    if (!needle) return true;
    var routes = [item.before, item.after].filter(Boolean);
    if (key === 'prefix') return item.prefix.toLowerCase().indexOf(needle) >= 0;
    for (var i = 0; i < routes.length; i += 1) {
      var paths = routes[i].paths || [];
      for (var j = 0; j < paths.length; j += 1) {
        var value = key === 'nextHop' ? paths[j].nextHop : paths[j].outInterface;
        if (String(value || '').toLowerCase().indexOf(needle) >= 0) return true;
      }
    }
    return false;
  }

  function filteredResults() {
    if (!state.diff) return [];
    readFilters();
    return state.diff.results.filter(function (item) {
      if (state.filters.vrf !== 'all' && item.vrf !== state.filters.vrf) return false;
      if (state.filters.type === 'non-unchanged' && item.type === 'unchanged') return false;
      if (state.filters.type !== 'all' && state.filters.type !== 'non-unchanged' && item.type !== state.filters.type) return false;
      if (state.filters.protocol !== 'all' && item.protocol !== state.filters.protocol) return false;
      if (!matchesRouteSearch(item, 'prefix', state.filters.prefix)) return false;
      if (!matchesRouteSearch(item, 'nextHop', state.filters.nextHop)) return false;
      if (!matchesRouteSearch(item, 'iface', state.filters.iface)) return false;
      return true;
    });
  }

  function renderSummary() {
    var totals = state.diff.totals;
    $('summaryCards').innerHTML = [
      ['Total VRFs', state.diff.totalVrfs],
      ['Added', totals.added],
      ['Removed', totals.removed],
      ['Changed', totals.changed],
      ['Unchanged', totals.unchanged],
      ['Parse warnings', state.diff.parseWarnings.length]
    ].map(function (item) {
      return '<div class="metric"><span>' + escapeHtml(item[0]) + '</span><strong>' + escapeHtml(item[1]) + '</strong></div>';
    }).join('');
  }

  function renderVrfSummary() {
    $('vrfSummaryBody').innerHTML = state.diff.vrfSummary.map(function (row) {
      return '<tr><th scope="row">' + escapeHtml(row.vrf) + '</th>' +
        '<td>' + row.added + '</td><td>' + row.removed + '</td><td>' + row.changed + '</td><td>' + row.unchanged + '</td></tr>';
    }).join('') || '<tr><td colspan="5">No routes parsed.</td></tr>';
  }

  function renderChangeDetails(item) {
    if (item.type !== 'changed') return '';
    var rows = item.changes.map(function (change) {
      if (change.field === 'paths') {
        return '<div><strong>' + escapeHtml(change.label) + '</strong>' +
          '<div class="detail-grid"><span>Next-hop removed</span><code>' + escapeHtml(pathsText(change.pathRemoved)) + '</code>' +
          '<span>Next-hop added</span><code>' + escapeHtml(pathsText(change.pathAdded)) + '</code></div></div>';
      }
      return '<div><strong>' + escapeHtml(change.label) + '</strong>' +
        '<div class="detail-grid"><span>before</span><code>' + escapeHtml(change.before) + '</code>' +
        '<span>after</span><code>' + escapeHtml(change.after) + '</code></div></div>';
    }).join('');
    return '<details><summary>Changed fields: ' + escapeHtml(item.changes.map(function (c) { return c.label; }).join(', ')) + '</summary>' +
      '<div class="details-body"><p><strong>Prefix:</strong> ' + escapeHtml(item.prefix) + ' / <strong>VRF:</strong> ' + escapeHtml(item.vrf) + '</p>' +
      '<div class="detail-grid"><span>Before</span><code>' + escapeHtml(routeText(item.before)) + '</code>' +
      '<span>After</span><code>' + escapeHtml(routeText(item.after)) + '</code></div>' + rows + '</div></details>';
  }

  function renderResults() {
    var rows = filteredResults();
    $('resultCount').textContent = rows.length + ' routes shown';
    $('diffBody').innerHTML = rows.map(function (item) {
      var typeClass = 'badge badge-' + item.type;
      return '<tr>' +
        '<td><span class="' + typeClass + '">' + escapeHtml(titleCase(item.type)) + '</span></td>' +
        '<td>' + escapeHtml(item.vrf) + '</td>' +
        '<td><code>' + escapeHtml(item.prefix) + '</code></td>' +
        '<td>' + escapeHtml(item.protocol || '-') + '</td>' +
        '<td>' + escapeHtml(routeText(item.before)) + '</td>' +
        '<td>' + escapeHtml(routeText(item.after)) + renderChangeDetails(item) + '</td>' +
        '</tr>';
    }).join('') || '<tr><td colspan="6">No routes match the current filters.</td></tr>';
  }

  function renderWarnings() {
    var warnings = state.diff.parseWarnings;
    $('warningsList').innerHTML = warnings.map(function (warning) {
      return '<li><strong>' + escapeHtml(warning.side || '') + ' line ' + warning.line + ':</strong> ' +
        escapeHtml(warning.message) + '<br><code>' + escapeHtml(warning.content) + '</code></li>';
    }).join('') || '<li>No parse warnings.</li>';
  }

  function render() {
    if (!state.diff) return;
    renderSummary();
    renderVrfSummary();
    renderResults();
    renderWarnings();
  }

  function clearAll() {
    $('beforeInput').value = '';
    $('afterInput').value = '';
    $('resultsPanel').hidden = true;
    state.beforeParse = null;
    state.afterParse = null;
    state.diff = null;
  }

  function loadSample() {
    $('beforeInput').value = SAMPLE_BEFORE;
    $('afterInput').value = SAMPLE_AFTER;
    parseAndDiff();
  }

  function csvEscape(value) {
    value = String(value === null || value === undefined ? '' : value);
    return /[",\n]/.test(value) ? '"' + value.replace(/"/g, '""') + '"' : value;
  }

  function rowsForExport() {
    return (state.diff ? state.diff.results : []).map(function (item) {
      return {
        type: item.type,
        vrf: item.vrf,
        afi: item.afi,
        prefix: item.prefix,
        protocol: item.protocol,
        before: routeText(item.before),
        after: routeText(item.after),
        change: window.RouteDiff.summarizeChange(item)
      };
    });
  }

  function download(filename, content, type) {
    var blob = new Blob([content], { type: type });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  function copyMarkdown() {
    if (!state.diff) return;
    var totals = state.diff.totals;
    var changedRows = state.diff.results.filter(function (item) { return item.type === 'changed'; });
    var markdown = '# Route Diff Summary\n\n' +
      '## Summary\n\n' +
      '- Total VRFs: ' + state.diff.totalVrfs + '\n' +
      '- Added: ' + totals.added + '\n' +
      '- Removed: ' + totals.removed + '\n' +
      '- Changed: ' + totals.changed + '\n' +
      '- Unchanged: ' + totals.unchanged + '\n' +
      '- Parse warnings: ' + state.diff.parseWarnings.length + '\n\n' +
      '## VRF Summary\n\n' +
      '| VRF | Added | Removed | Changed | Unchanged |\n|---|---:|---:|---:|---:|\n' +
      state.diff.vrfSummary.map(function (row) {
        return '| ' + row.vrf + ' | ' + row.added + ' | ' + row.removed + ' | ' + row.changed + ' | ' + row.unchanged + ' |';
      }).join('\n') + '\n\n' +
      '## Changed Routes\n\n' +
      '| VRF | Prefix | Change |\n|---|---|---|\n' +
      changedRows.map(function (item) {
        return '| ' + item.vrf + ' | ' + item.prefix + ' | ' + window.RouteDiff.summarizeChange(item) + ' |';
      }).join('\n') + '\n';

    copyText(markdown, 'Copied Markdown summary.');
  }

  function copyText(text, successMessage) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        $('copyStatus').textContent = successMessage;
      }, function () {
        fallbackCopyText(text, successMessage);
      });
      return;
    }
    fallbackCopyText(text, successMessage);
  }

  function fallbackCopyText(text, successMessage) {
    var scratch = document.createElement('textarea');
    scratch.value = text;
    scratch.setAttribute('readonly', 'readonly');
    scratch.style.position = 'fixed';
    scratch.style.left = '-9999px';
    document.body.appendChild(scratch);
    scratch.select();
    try {
      if (document.execCommand && document.execCommand('copy')) {
        $('copyStatus').textContent = successMessage;
      } else {
        $('copyStatus').textContent = 'Clipboard copy is blocked by this browser. Download CSV/JSON or select the generated text manually.';
      }
    } catch (error) {
      $('copyStatus').textContent = 'Clipboard copy is blocked by this browser. Download CSV/JSON instead.';
    }
    document.body.removeChild(scratch);
  }

  function downloadCsv() {
    var rows = rowsForExport();
    var header = ['Type', 'VRF', 'AFI', 'Prefix', 'Protocol', 'Before', 'After', 'Change'];
    var csv = header.join(',') + '\n' + rows.map(function (row) {
      return [row.type, row.vrf, row.afi, row.prefix, row.protocol, row.before, row.after, row.change].map(csvEscape).join(',');
    }).join('\n') + '\n';
    download('route-diff.csv', csv, 'text/csv;charset=utf-8');
  }

  function downloadJson() {
    download('route-diff.json', JSON.stringify(state.diff, null, 2), 'application/json');
  }

  function downloadRoutesJson() {
    var normalized = {
      before: state.beforeParse ? state.beforeParse.routes : [],
      after: state.afterParse ? state.afterParse.routes : []
    };
    download('normalized-routes.json', JSON.stringify(normalized, null, 2), 'application/json');
  }

  function bind() {
    $('parseBtn').addEventListener('click', parseAndDiff);
    $('clearBtn').addEventListener('click', clearAll);
    $('sampleBtn').addEventListener('click', loadSample);
    $('copyMarkdownBtn').addEventListener('click', copyMarkdown);
    $('downloadCsvBtn').addEventListener('click', downloadCsv);
    $('downloadJsonBtn').addEventListener('click', downloadJson);
    $('downloadRoutesBtn').addEventListener('click', downloadRoutesJson);
    ['filterVrf', 'filterType', 'filterProtocol', 'filterPrefix', 'filterNextHop', 'filterInterface'].forEach(function (id) {
      $(id).addEventListener('input', renderResults);
      $(id).addEventListener('change', renderResults);
    });
  }

  document.addEventListener('DOMContentLoaded', bind);
  window.CiscoRouteDiffApp = {
    parseAndDiff: parseAndDiff,
    loadSample: loadSample,
    getState: function () { return state; }
  };
}());
