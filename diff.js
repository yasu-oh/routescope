(function (global) {
  'use strict';

  function routeIdentityKey(route) {
    return [route.vrf, route.afi, route.prefix, route.protocol, route.routeType].join('|');
  }

  function routeMatchKey(route) {
    return [route.vrf, route.afi, route.prefix].join('|');
  }

  function routeSortKey(route) {
    return [route.protocol || '', route.routeType || '', route.signature || routeIdentityKey(route)].join('|');
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
    return [path.kind || '', path.nextHop || '', path.outInterface || ''].join('|');
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

    function routeTieKey(pairList) {
      return pairList.map(function (pair) {
        return routeSortKey(pair.before) + '=>' + routeSortKey(pair.after);
      }).sort().join('\n');
    }

    function consider(score) {
      var ordered = current.slice();
      if (score > bestScore || (score === bestScore && routeTieKey(ordered) < routeTieKey(bestPairs))) {
        bestScore = score;
        bestPairs = ordered;
      }
    }

    function search(score) {
      if (current.length === pairCount) {
        consider(score);
        return;
      }
      var i;
      var beforeIndex = -1;
      var afterIndex = -1;
      if (before.length <= after.length) {
        for (i = 0; i < before.length; i += 1) {
          if (!usedBefore[i]) {
            beforeIndex = i;
            break;
          }
        }
        for (var ai = 0; ai < after.length; ai += 1) {
          if (usedAfter[ai]) continue;
          usedBefore[beforeIndex] = true;
          usedAfter[ai] = true;
          current.push({ before: before[beforeIndex], after: after[ai] });
          search(score + routePairScore(before[beforeIndex], after[ai]));
          current.pop();
          usedBefore[beforeIndex] = false;
          usedAfter[ai] = false;
        }
      } else {
        for (i = 0; i < after.length; i += 1) {
          if (!usedAfter[i]) {
            afterIndex = i;
            break;
          }
        }
        for (var bi = 0; bi < before.length; bi += 1) {
          if (usedBefore[bi]) continue;
          usedBefore[bi] = true;
          usedAfter[afterIndex] = true;
          current.push({ before: before[bi], after: after[afterIndex] });
          search(score + routePairScore(before[bi], after[afterIndex]));
          current.pop();
          usedBefore[bi] = false;
          usedAfter[afterIndex] = false;
        }
      }
    }

    search(0);
    return bestPairs;
  }

  function pairRoutes(beforeGroup, afterGroup) {
    var beforeRemaining = (beforeGroup || []).slice();
    var afterRemaining = (afterGroup || []).slice();
    var pairs = [];

    beforeRemaining.sort(function (a, b) { return routeSortKey(a).localeCompare(routeSortKey(b)); });
    afterRemaining.sort(function (a, b) { return routeSortKey(a).localeCompare(routeSortKey(b)); });

    // First preserve exact route identities. This avoids collapsing NX-OS local/direct
    // or multiple same-prefix protocol records when they are present on both sides.
    for (var i = beforeRemaining.length - 1; i >= 0; i -= 1) {
      var beforeRoute = beforeRemaining[i];
      var identity = routeIdentityKey(beforeRoute);
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

    // Pair remaining routes by same VRF/AFI/prefix as changed routes. Use an
    // optimal small-group assignment so multiple same-prefix protocol changes are
    // matched to the most similar counterpart, not merely the first greedy match.
    var changedPairs = optimalPairRemaining(beforeRemaining, afterRemaining);
    changedPairs.forEach(function (pair) {
      var beforeIndex = beforeRemaining.indexOf(pair.before);
      var afterIndex = afterRemaining.indexOf(pair.after);
      if (beforeIndex >= 0 && afterIndex >= 0) {
        pairs.push({ before: removeAt(beforeRemaining, beforeIndex), after: removeAt(afterRemaining, afterIndex) });
      }
    });

    while (beforeRemaining.length) pairs.push({ before: beforeRemaining.shift(), after: null });
    while (afterRemaining.length) pairs.push({ before: null, after: afterRemaining.shift() });

    pairs.sort(function (a, b) {
      var ak = routeSortKey(a.after || a.before);
      var bk = routeSortKey(b.after || b.before);
      return ak.localeCompare(bk);
    });
    return pairs;
  }

  function compare(beforeRoutes, afterRoutes, beforeWarnings, afterWarnings) {
    var beforeGroups = buildGroups(beforeRoutes || []);
    var afterGroups = buildGroups(afterRoutes || []);
    var keys = uniqueSorted(Object.keys(beforeGroups).concat(Object.keys(afterGroups)));
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
      var pairs = pairRoutes(beforeGroups[key] || [], afterGroups[key] || []);
      pairs.forEach(function (pair, index) {
        var beforeRoute = pair.before || null;
        var afterRoute = pair.after || null;
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
        var result = {
          key: key + '|' + index + '|' + routeIdentityKey(route),
          type: type,
          vrf: route.vrf,
          afi: route.afi,
          prefix: route.prefix,
          protocol: '',
          before: beforeRoute,
          after: afterRoute,
          changes: changes
        };
        result.protocol = protocolLabel(result);
        results.push(result);
      });
    });

    var vrfs = uniqueSorted(Object.keys(vrfSummary));
    var protocolValues = [];
    results.forEach(function (item) {
      protocolValues = protocolValues.concat(protocolsForResult(item));
    });
    var protocols = uniqueSorted(protocolValues.filter(Boolean));
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
