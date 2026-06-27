(function (global) {
  'use strict';

  var SCALAR_CHANGES = [
    ['protocol', 'protocol'],
    ['routeType', 'route type'],
    ['adminDistance', 'administrative distance'],
    ['metric', 'metric'],
    ['isDefaultCandidate', 'default candidate flag']
  ];

  function joinKey(parts) {
    return parts.map(function (part) { return part === null || part === undefined ? '' : part; }).join('|');
  }

  function routeIdentityKey(route) {
    return joinKey([route.vrf, route.afi, route.prefix, route.protocol, route.routeType]);
  }

  function routeMatchKey(route) {
    return joinKey([route.vrf, route.afi, route.prefix]);
  }

  function routeSortKey(route) {
    return joinKey([route.protocol, route.routeType, route.signature || routeIdentityKey(route)]);
  }

  function pathKey(path) {
    return joinKey([path.kind, path.nextHop, path.outInterface]);
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

  function pathSet(paths) {
    var set = Object.create(null);
    for (var i = 0; i < (paths || []).length; i += 1) {
      set[pathKey(paths[i])] = paths[i];
    }
    return set;
  }

  function buildGroups(routes) {
    var groups = Object.create(null);
    for (var i = 0; i < (routes || []).length; i += 1) {
      var route = routes[i];
      var key = routeMatchKey(route);
      if (!groups[key]) groups[key] = [];
      groups[key].push(route);
    }
    Object.keys(groups).forEach(function (key) {
      groups[key].sort(function (a, b) { return routeSortKey(a).localeCompare(routeSortKey(b)); });
    });
    return groups;
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

  function addScalarChanges(changes, beforeRoute, afterRoute) {
    SCALAR_CHANGES.forEach(function (item) {
      var field = item[0];
      var label = item[1];
      if (beforeRoute[field] !== afterRoute[field]) {
        changes.push({
          field: field,
          label: label,
          before: beforeRoute[field],
          after: afterRoute[field]
        });
      }
    });
  }

  function addPathChange(changes, beforeRoute, afterRoute) {
    var paths = diffPaths(beforeRoute.paths, afterRoute.paths);
    if (!paths.added.length && !paths.removed.length) return;
    changes.push({
      field: 'paths',
      label: 'next-hop/interface set',
      before: beforeRoute.paths,
      after: afterRoute.paths,
      pathAdded: paths.added,
      pathRemoved: paths.removed
    });
  }

  function compareRoutes(beforeRoute, afterRoute) {
    var changes = [];
    addScalarChanges(changes, beforeRoute, afterRoute);
    addPathChange(changes, beforeRoute, afterRoute);
    return changes;
  }

  function protocolsForResult(result) {
    var values = [];
    if (result.before && result.before.protocol) values.push(result.before.protocol);
    if (result.after && result.after.protocol) values.push(result.after.protocol);
    return uniqueSorted(values);
  }

  function protocolLabel(result) {
    var values = protocolsForResult(result);
    if (!values.length) return '';
    if (result.before && result.after && result.before.protocol !== result.after.protocol) {
      return (result.before.protocol || '-') + ' -> ' + (result.after.protocol || '-');
    }
    return values[0];
  }

  function routePairScore(beforeRoute, afterRoute) {
    var score = 0;
    if (beforeRoute.protocol === afterRoute.protocol) score += 100;
    if (beforeRoute.routeType === afterRoute.routeType) score += 40;
    if (beforeRoute.isDefaultCandidate === afterRoute.isDefaultCandidate) score += 10;
    if (beforeRoute.adminDistance === afterRoute.adminDistance) score += 5;
    if (beforeRoute.metric === afterRoute.metric) score += 5;

    var beforePaths = pathSet(beforeRoute.paths);
    var afterPaths = pathSet(afterRoute.paths);
    Object.keys(beforePaths).forEach(function (key) {
      if (afterPaths[key]) score += 3;
    });
    return score;
  }

  function removeAt(array, index) {
    var item = array[index];
    array.splice(index, 1);
    return item;
  }

  function takeExactIdentityPairs(beforeRemaining, afterRemaining) {
    var pairs = [];
    for (var i = beforeRemaining.length - 1; i >= 0; i -= 1) {
      var identity = routeIdentityKey(beforeRemaining[i]);
      var matchedIndex = -1;
      for (var j = 0; j < afterRemaining.length; j += 1) {
        if (routeIdentityKey(afterRemaining[j]) === identity) {
          matchedIndex = j;
          break;
        }
      }
      if (matchedIndex >= 0) {
        pairs.push({ before: removeAt(beforeRemaining, i), after: removeAt(afterRemaining, matchedIndex) });
      }
    }
    return pairs;
  }

  function greedyPairRemaining(beforeRemaining, afterRemaining) {
    var pairs = [];
    while (beforeRemaining.length && afterRemaining.length) {
      var bestBefore = 0;
      var bestAfter = 0;
      var bestScore = -1;
      for (var bi = 0; bi < beforeRemaining.length; bi += 1) {
        for (var ai = 0; ai < afterRemaining.length; ai += 1) {
          var score = routePairScore(beforeRemaining[bi], afterRemaining[ai]);
          if (score > bestScore) {
            bestScore = score;
            bestBefore = bi;
            bestAfter = ai;
          }
        }
      }
      pairs.push({ before: removeAt(beforeRemaining, bestBefore), after: removeAt(afterRemaining, bestAfter) });
    }
    return pairs;
  }

  function pairTieKey(pairList) {
    return pairList.map(function (pair) {
      return routeSortKey(pair.before) + '=>' + routeSortKey(pair.after);
    }).sort().join('\n');
  }

  function optimalPairRemaining(beforeRemaining, afterRemaining) {
    var before = beforeRemaining.slice();
    var after = afterRemaining.slice();
    var pairCount = Math.min(before.length, after.length);
    if (!pairCount) return [];
    if (Math.max(before.length, after.length) > 8) return greedyPairRemaining(before, after);

    var bestScore = -Infinity;
    var bestPairs = [];
    var usedBefore = [];
    var usedAfter = [];
    var current = [];

    function consider(score) {
      var candidate = current.slice();
      if (score > bestScore || (score === bestScore && pairTieKey(candidate) < pairTieKey(bestPairs))) {
        bestScore = score;
        bestPairs = candidate;
      }
    }

    function search(score) {
      if (current.length === pairCount) {
        consider(score);
        return;
      }
      var i;
      var anchorIndex = -1;
      if (before.length <= after.length) {
        for (i = 0; i < before.length; i += 1) {
          if (!usedBefore[i]) {
            anchorIndex = i;
            break;
          }
        }
        for (var ai = 0; ai < after.length; ai += 1) {
          if (usedAfter[ai]) continue;
          usedBefore[anchorIndex] = true;
          usedAfter[ai] = true;
          current.push({ before: before[anchorIndex], after: after[ai] });
          search(score + routePairScore(before[anchorIndex], after[ai]));
          current.pop();
          usedBefore[anchorIndex] = false;
          usedAfter[ai] = false;
        }
      } else {
        for (i = 0; i < after.length; i += 1) {
          if (!usedAfter[i]) {
            anchorIndex = i;
            break;
          }
        }
        for (var bi = 0; bi < before.length; bi += 1) {
          if (usedBefore[bi]) continue;
          usedBefore[bi] = true;
          usedAfter[anchorIndex] = true;
          current.push({ before: before[bi], after: after[anchorIndex] });
          search(score + routePairScore(before[bi], after[anchorIndex]));
          current.pop();
          usedBefore[bi] = false;
          usedAfter[anchorIndex] = false;
        }
      }
    }

    search(0);
    return bestPairs;
  }

  function appendChangedPairs(pairs, beforeRemaining, afterRemaining) {
    var changedPairs = optimalPairRemaining(beforeRemaining, afterRemaining);
    changedPairs.forEach(function (pair) {
      var beforeIndex = beforeRemaining.indexOf(pair.before);
      var afterIndex = afterRemaining.indexOf(pair.after);
      if (beforeIndex >= 0 && afterIndex >= 0) {
        pairs.push({ before: removeAt(beforeRemaining, beforeIndex), after: removeAt(afterRemaining, afterIndex) });
      }
    });
  }

  function pairRoutes(beforeGroup, afterGroup) {
    var beforeRemaining = (beforeGroup || []).slice();
    var afterRemaining = (afterGroup || []).slice();
    var pairs = [];

    beforeRemaining.sort(function (a, b) { return routeSortKey(a).localeCompare(routeSortKey(b)); });
    afterRemaining.sort(function (a, b) { return routeSortKey(a).localeCompare(routeSortKey(b)); });

    pairs = pairs.concat(takeExactIdentityPairs(beforeRemaining, afterRemaining));
    appendChangedPairs(pairs, beforeRemaining, afterRemaining);

    while (beforeRemaining.length) pairs.push({ before: beforeRemaining.shift(), after: null });
    while (afterRemaining.length) pairs.push({ before: null, after: afterRemaining.shift() });

    pairs.sort(function (a, b) {
      return routeSortKey(a.after || a.before).localeCompare(routeSortKey(b.after || b.before));
    });
    return pairs;
  }

  function classifyPair(pair) {
    if (!pair.before && pair.after) return { type: 'added', changes: [] };
    if (pair.before && !pair.after) return { type: 'removed', changes: [] };
    var changes = compareRoutes(pair.before, pair.after);
    return { type: changes.length ? 'changed' : 'unchanged', changes: changes };
  }

  function makeResult(pair, groupKey, index) {
    var route = pair.after || pair.before;
    var classification = classifyPair(pair);
    var result = {
      key: groupKey + '|' + index + '|' + routeIdentityKey(route),
      type: classification.type,
      vrf: route.vrf,
      afi: route.afi,
      prefix: route.prefix,
      protocol: '',
      before: pair.before || null,
      after: pair.after || null,
      changes: classification.changes
    };
    result.protocol = protocolLabel(result);
    return result;
  }

  function makeVrfSummary() {
    return { added: 0, removed: 0, changed: 0, unchanged: 0 };
  }

  function compare(beforeRoutes, afterRoutes, beforeWarnings, afterWarnings) {
    var beforeGroups = buildGroups(beforeRoutes || []);
    var afterGroups = buildGroups(afterRoutes || []);
    var keys = uniqueSorted(Object.keys(beforeGroups).concat(Object.keys(afterGroups)));
    var results = [];
    var totals = makeVrfSummary();
    var vrfSummary = Object.create(null);

    function ensureVrf(vrf) {
      if (!vrfSummary[vrf]) {
        vrfSummary[vrf] = { vrf: vrf, added: 0, removed: 0, changed: 0, unchanged: 0 };
      }
      return vrfSummary[vrf];
    }

    keys.forEach(function (key) {
      var pairs = pairRoutes(beforeGroups[key] || [], afterGroups[key] || []);
      pairs.forEach(function (pair, index) {
        var result = makeResult(pair, key, index);
        totals[result.type] += 1;
        ensureVrf(result.vrf)[result.type] += 1;
        results.push(result);
      });
    });

    var vrfs = uniqueSorted(Object.keys(vrfSummary));
    var protocolValues = [];
    results.forEach(function (item) {
      protocolValues = protocolValues.concat(protocolsForResult(item));
    });

    return {
      results: results,
      totals: totals,
      vrfSummary: vrfs.map(function (vrf) { return vrfSummary[vrf]; }),
      vrfs: vrfs,
      protocols: uniqueSorted(protocolValues.filter(Boolean)),
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
    summarizeChange: summarizeChange,
    _internals: {
      routeIdentityKey: routeIdentityKey,
      routeMatchKey: routeMatchKey,
      pathKey: pathKey,
      pairRoutes: pairRoutes,
      routePairScore: routePairScore
    }
  };
}(window));
