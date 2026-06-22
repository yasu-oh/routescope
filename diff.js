(function (global) {
  'use strict';

  function routeKey(route) {
    return [route.vrf, route.afi, route.prefix].join('|');
  }

  function buildMap(routes) {
    var map = Object.create(null);
    for (var i = 0; i < routes.length; i += 1) {
      map[routeKey(routes[i])] = routes[i];
    }
    return map;
  }

  function uniqueSorted(values) {
    var seen = Object.create(null);
    var output = [];
    for (var i = 0; i < values.length; i += 1) {
      var value = values[i];
      if (!seen[value]) {
        seen[value] = true;
        output.push(value);
      }
    }
    output.sort(function (a, b) { return a.localeCompare(b); });
    return output;
  }

  function pathKey(path) {
    return global.RouteDiffParser.pathKey(path);
  }

  function pathSet(paths) {
    var set = Object.create(null);
    for (var i = 0; i < (paths || []).length; i += 1) {
      set[pathKey(paths[i])] = paths[i];
    }
    return set;
  }

  function diffPaths(beforePaths, afterPaths) {
    var beforeSet = pathSet(beforePaths);
    var afterSet = pathSet(afterPaths);
    var added = [];
    var removed = [];
    Object.keys(afterSet).sort().forEach(function (key) {
      if (!beforeSet[key]) added.push(afterSet[key]);
    });
    Object.keys(beforeSet).sort().forEach(function (key) {
      if (!afterSet[key]) removed.push(beforeSet[key]);
    });
    return { added: added, removed: removed };
  }

  function compareRoutes(beforeRoute, afterRoute) {
    var changes = [];
    function check(field, label) {
      if (beforeRoute[field] !== afterRoute[field]) {
        changes.push({
          field: field,
          label: label || field,
          before: beforeRoute[field],
          after: afterRoute[field]
        });
      }
    }

    check('protocol', 'protocol');
    check('routeType', 'route type');
    check('adminDistance', 'administrative distance');
    check('metric', 'metric');
    check('isDefaultCandidate', 'default candidate flag');

    var paths = diffPaths(beforeRoute.paths, afterRoute.paths);
    if (paths.added.length || paths.removed.length) {
      changes.push({
        field: 'paths',
        label: 'next-hop/interface set',
        before: beforeRoute.paths,
        after: afterRoute.paths,
        pathAdded: paths.added,
        pathRemoved: paths.removed
      });
    }

    return changes;
  }

  function protocolOf(result) {
    var route = result.after || result.before;
    return route ? route.protocol : '';
  }

  function compare(beforeRoutes, afterRoutes, beforeWarnings, afterWarnings) {
    var beforeMap = buildMap(beforeRoutes || []);
    var afterMap = buildMap(afterRoutes || []);
    var keys = uniqueSorted(Object.keys(beforeMap).concat(Object.keys(afterMap)));
    var results = [];
    var totals = { added: 0, removed: 0, changed: 0, unchanged: 0 };
    var vrfSummary = Object.create(null);

    function ensureVrf(vrf) {
      if (!vrfSummary[vrf]) {
        vrfSummary[vrf] = { vrf: vrf, added: 0, removed: 0, changed: 0, unchanged: 0 };
      }
      return vrfSummary[vrf];
    }

    keys.forEach(function (key) {
      var beforeRoute = beforeMap[key] || null;
      var afterRoute = afterMap[key] || null;
      var route = afterRoute || beforeRoute;
      var type = 'unchanged';
      var changes = [];
      if (!beforeRoute && afterRoute) {
        type = 'added';
      } else if (beforeRoute && !afterRoute) {
        type = 'removed';
      } else {
        changes = compareRoutes(beforeRoute, afterRoute);
        type = changes.length ? 'changed' : 'unchanged';
      }
      totals[type] += 1;
      ensureVrf(route.vrf)[type] += 1;
      results.push({
        key: key,
        type: type,
        vrf: route.vrf,
        afi: route.afi,
        prefix: route.prefix,
        protocol: protocolOf({ before: beforeRoute, after: afterRoute }),
        before: beforeRoute,
        after: afterRoute,
        changes: changes
      });
    });

    var vrfs = uniqueSorted(Object.keys(vrfSummary));
    var protocols = uniqueSorted(results.map(function (item) { return item.protocol; }).filter(Boolean));
    return {
      results: results,
      totals: totals,
      vrfSummary: vrfs.map(function (vrf) { return vrfSummary[vrf]; }),
      vrfs: vrfs,
      protocols: protocols,
      parseWarnings: (beforeWarnings || []).concat(afterWarnings || []),
      totalVrfs: vrfs.length
    };
  }

  function summarizeChange(item) {
    if (item.type === 'added') return 'added';
    if (item.type === 'removed') return 'removed';
    if (item.type === 'unchanged') return 'unchanged';
    return item.changes.map(function (change) { return change.label; }).join(', ');
  }

  global.RouteDiff = {
    compare: compare,
    compareRoutes: compareRoutes,
    diffPaths: diffPaths,
    summarizeChange: summarizeChange
  };
}(window));
