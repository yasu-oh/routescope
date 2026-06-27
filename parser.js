(function (global) {
  'use strict';

  var IPV4_ADDRESS = '(?:\\d{1,3}\\.){3}\\d{1,3}';
  var IPV4_PREFIX = IPV4_ADDRESS + '(?:\\/\\d{1,2})?';
  var IPV6_ADDRESS = '(?:[0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f:.]{0,39}';
  var IPV6_PREFIX = IPV6_ADDRESS + '\\/\\d{1,3}';
  var ROUTE_PREFIX = '(?:' + IPV4_PREFIX + '|' + IPV6_PREFIX + ')';
  var ROUTE_START_RE = new RegExp('^\\s*([A-Za-z][A-Za-z0-9*]*)(?:\\s+([A-Za-z0-9*]+))?\\s+(' + ROUTE_PREFIX + ')(.*)$');
  var CONTINUATION_RE = /^\s+(?:\[(\d+)\/(\d+)\]\s+)?via\s+(\S+)(.*)$/i;
  var AD_METRIC_RE = /\[(\d+)\/(\d+)\]/;
  var AGE_TOKEN_RE = /^(?:\d{1,2}:\d{2}:\d{2}|\d+w\d+d|\d+d\d+h|\d+h\d+m|\d+m\d+s|\d+[wdhms])$/i;

  function stripAnsi(value) {
    return String(value || '').replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '');
  }

  function normalizeLine(line) {
    return stripAnsi(line).replace(/--More--/g, '').replace(/\r/g, '').trimEnd();
  }

  function isIgnorableLine(line) {
    var trimmed = line.trim();
    if (!trimmed) return true;
    if (/^(Codes|Last update|Route metric is|Routing entry for|Known via|Redistributing via|Distance:|Tag|Attached|ubest\/mbest|Address Family):/i.test(trimmed)) return true;
    if (/^Gateway of last resort\b/i.test(trimmed)) return true;
    if (/^[A-Z+&%*][A-Z0-9+&%* ]{0,4}\s+-\s+/i.test(trimmed)) return true;
    if (/^\*?\s*\d+\s+subnets?,\s+\d+\s+masks?/i.test(trimmed)) return true;
    if (/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\s+is\s+(?:variably\s+)?subnetted/i.test(trimmed)) return true;
    if (/^\S+[>#]\s*$/i.test(trimmed)) return true;
    if (/^Load for five secs:/i.test(trimmed)) return true;
    if (/^Time source is/i.test(trimmed)) return true;
    return false;
  }

  function parseCommandVrf(line) {
    var match = line.match(/(?:^|[>#]\s*)show\s+(?:p\s+)?(?:ip|ipv6)\s+route(?:\s+vrf\s+(\S+))?/i);
    if (!match) return null;
    if (match[1] && match[1].toLowerCase() !== 'all' && match[1] !== '*') return match[1];
    return 'global';
  }

  function parseVrfHeader(line) {
    var match = line.match(/^\s*Routing Table:\s*(.+?)\s*$/i);
    if (match) return cleanVrfName(match[1]);
    match = line.match(/^\s*IPv6 Routing Table\s+-\s+(.+?)\s+-\s+\d+\s+entries/i);
    if (match) return cleanVrfName(match[1]);
    match = line.match(/^\s*IP Route Table for VRF\s+"?([^"\s]+)"?/i);
    if (match) return cleanVrfName(match[1]);
    return null;
  }

  function cleanVrfName(name) {
    return String(name || 'global').replace(/^"|"$/g, '').trim() || 'global';
  }

  function parseSubnetHeader(line) {
    var match = String(line || '').match(/^\s*(?:\d{1,3}\.){3}\d{1,3}\/(\d{1,2})\s+is\s+(?:variably\s+)?subnetted/i);
    if (!match) return null;
    return Number(match[1]);
  }

  function inferClassfulPrefixLength(address) {
    var firstOctet = Number(String(address || '').split('.')[0]);
    if (firstOctet === 0) return 0;
    if (firstOctet >= 1 && firstOctet <= 126) return 8;
    if (firstOctet >= 128 && firstOctet <= 191) return 16;
    if (firstOctet >= 192 && firstOctet <= 223) return 24;
    return 32;
  }

  function normalizePrefix(prefix, inheritedPrefixLength) {
    prefix = String(prefix || '').trim();
    if (prefix.indexOf('/') >= 0) return prefix;
    var prefixLength = typeof inheritedPrefixLength === 'number' ? inheritedPrefixLength : inferClassfulPrefixLength(prefix);
    return prefix + '/' + prefixLength;
  }

  function parseRouteCode(protocolToken, routeTypeToken) {
    var rawProtocol = String(protocolToken || '').trim();
    var rawRouteType = String(routeTypeToken || '').trim();
    var isDefaultCandidate = /\*/.test(rawProtocol + rawRouteType);
    var protocol = rawProtocol.replace(/\*/g, '');
    var routeType = rawRouteType.replace(/\*/g, '');
    var suffixes = ['IA', 'E1', 'E2', 'N1', 'N2', 'EX', 'I'];

    if (!routeType) {
      for (var i = 0; i < suffixes.length; i += 1) {
        var suffix = suffixes[i];
        if (protocol.length > suffix.length && protocol.slice(protocol.length - suffix.length) === suffix) {
          routeType = suffix;
          protocol = protocol.slice(0, protocol.length - suffix.length);
          break;
        }
      }
    }

    return {
      protocol: protocol,
      routeType: routeType,
      isDefaultCandidate: isDefaultCandidate
    };
  }

  function parseAdMetric(text) {
    var match = String(text || '').match(AD_METRIC_RE);
    if (!match) return { adminDistance: null, metric: null };
    return { adminDistance: Number(match[1]), metric: Number(match[2]) };
  }

  function sanitizeToken(token) {
    return String(token || '').replace(/[(),]/g, '').trim();
  }

  function isIpv4Address(token) {
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(sanitizeToken(token));
  }

  function isIpv6Address(token) {
    token = sanitizeToken(token);
    return token.indexOf(':') >= 0 && /^[0-9A-Fa-f:.]+$/.test(token);
  }

  function isIpAddress(token) {
    return isIpv4Address(token) || isIpv6Address(token);
  }

  function detectAfi(prefix) {
    return String(prefix || '').indexOf(':') >= 0 ? 'ipv6' : 'ipv4';
  }

  function looksLikeInterface(token) {
    token = sanitizeToken(token);
    if (!token) return false;
    if (AGE_TOKEN_RE.test(token)) return false;
    if (/^\[\d+\/\d+\]$/.test(token)) return false;
    if (/^(via|is|directly|connected)$/i.test(token)) return false;
    if (isIpAddress(token)) return false;
    return true;
  }

  function parsePathFromVia(rest) {
    var match = String(rest || '').match(/via\s+(\S+)(.*)$/i);
    if (!match) return null;
    var firstToken = sanitizeToken(match[1]);
    var tail = match[2] || '';
    var outInterface = '';
    var parts = tail.split(',');
    for (var i = parts.length - 1; i >= 0; i -= 1) {
      var token = sanitizeToken(parts[i]);
      if (looksLikeInterface(token)) {
        outInterface = token;
        break;
      }
    }
    if (isIpAddress(firstToken)) {
      return {
        nextHop: firstToken,
        outInterface: outInterface,
        kind: 'via'
      };
    }
    if (/directly\s+connected/i.test(tail)) {
      return {
        nextHop: '',
        outInterface: firstToken,
        kind: 'connected'
      };
    }
    if (/receive/i.test(tail)) {
      return {
        nextHop: '',
        outInterface: firstToken,
        kind: 'receive'
      };
    }
    return {
      nextHop: '',
      outInterface: firstToken,
      kind: 'interface'
    };
  }

  function parsePathFromConnected(rest) {
    var match = String(rest || '').match(/is\s+directly\s+connected\s*,\s*(\S+)/i);
    if (!match) return null;
    return {
      nextHop: '',
      outInterface: sanitizeToken(match[1]),
      kind: 'connected'
    };
  }

  function pathKey(path) {
    return [path.kind || '', path.nextHop || '', path.outInterface || ''].join('|');
  }

  function sortAndDedupePaths(paths) {
    var seen = Object.create(null);
    var output = [];
    for (var i = 0; i < paths.length; i += 1) {
      var path = paths[i];
      var key = pathKey(path);
      if (!seen[key]) {
        seen[key] = true;
        output.push({
          nextHop: path.nextHop || '',
          outInterface: path.outInterface || '',
          kind: path.kind || (path.nextHop ? 'via' : 'connected')
        });
      }
    }
    output.sort(function (a, b) {
      return pathKey(a).localeCompare(pathKey(b));
    });
    return output;
  }

  function normalizeRoute(route) {
    route.paths = sortAndDedupePaths(route.paths || []);
    route.key = [route.vrf, route.afi, route.prefix].join('|');
    route.signature = JSON.stringify({
      protocol: route.protocol,
      routeType: route.routeType,
      adminDistance: route.adminDistance,
      metric: route.metric,
      isDefaultCandidate: route.isDefaultCandidate,
      paths: route.paths
    });
    return route;
  }

  function makeRoute(vrf, protocolToken, routeTypeToken, prefix, rest, rawLine, inheritedPrefixLength) {
    var adMetric = parseAdMetric(rest);
    var routeCode = parseRouteCode(protocolToken, routeTypeToken);
    var connectedPath = parsePathFromConnected(rest);
    var viaPath = parsePathFromVia(rest);
    return normalizeRoute({
      vrf: vrf || 'global',
      afi: detectAfi(prefix),
      prefix: normalizePrefix(prefix, inheritedPrefixLength),
      protocol: routeCode.protocol,
      routeType: routeCode.routeType,
      adminDistance: adMetric.adminDistance,
      metric: adMetric.metric,
      isDefaultCandidate: routeCode.isDefaultCandidate,
      paths: connectedPath ? [connectedPath] : (viaPath ? [viaPath] : []),
      rawLines: [rawLine]
    });
  }

  function parseRouteLine(line, currentVrf, inheritedPrefixLength) {
    var match = line.match(ROUTE_START_RE);
    if (!match) return null;
    return makeRoute(currentVrf, match[1], match[2] || '', match[3], match[4] || '', line.trim(), inheritedPrefixLength);
  }

  function parseContinuationLine(line) {
    var match = line.match(CONTINUATION_RE);
    if (!match) return null;
    var rest = 'via ' + match[3] + (match[4] || '');
    var path = parsePathFromVia(rest);
    if (!path) return null;
    return {
      adminDistance: match[1] ? Number(match[1]) : null,
      metric: match[2] ? Number(match[2]) : null,
      path: path
    };
  }

  function routeMapFromRoutes(routes) {
    var map = Object.create(null);
    for (var i = 0; i < routes.length; i += 1) {
      var route = normalizeRoute(routes[i]);
      if (map[route.key]) {
        map[route.key].paths = sortAndDedupePaths(map[route.key].paths.concat(route.paths));
        map[route.key].rawLines = map[route.key].rawLines.concat(route.rawLines);
        map[route.key] = normalizeRoute(map[route.key]);
      } else {
        map[route.key] = route;
      }
    }
    return map;
  }

  function parse(text) {
    var currentVrf = 'global';
    var routes = [];
    var warnings = [];
    var lastRoute = null;
    var inheritedPrefixLength = null;
    var lines = String(text || '').split(/\n/);

    for (var index = 0; index < lines.length; index += 1) {
      var raw = lines[index];
      var line = normalizeLine(raw);
      var lineNumber = index + 1;
      var commandVrf = parseCommandVrf(line);
      if (commandVrf) {
        currentVrf = commandVrf;
        lastRoute = null;
        inheritedPrefixLength = null;
        continue;
      }
      var headerVrf = parseVrfHeader(line);
      if (headerVrf) {
        currentVrf = headerVrf;
        lastRoute = null;
        inheritedPrefixLength = null;
        continue;
      }
      var subnetPrefixLength = parseSubnetHeader(line);
      if (subnetPrefixLength !== null) {
        inheritedPrefixLength = subnetPrefixLength;
        lastRoute = null;
        continue;
      }
      if (isIgnorableLine(line)) continue;

      var route = parseRouteLine(line, currentVrf, inheritedPrefixLength);
      if (route) {
        routes.push(route);
        lastRoute = route;
        continue;
      }

      var continuation = parseContinuationLine(line);
      if (continuation) {
        if (!lastRoute) {
          warnings.push({ line: lineNumber, message: 'Continuation line without previous prefix', content: line.trim() });
          continue;
        }
        lastRoute.rawLines.push(line.trim());
        if (continuation.adminDistance !== null) lastRoute.adminDistance = continuation.adminDistance;
        if (continuation.metric !== null) lastRoute.metric = continuation.metric;
        lastRoute.paths.push(continuation.path);
        normalizeRoute(lastRoute);
        continue;
      }

      warnings.push({ line: lineNumber, message: 'Could not parse route line', content: line.trim() });
    }

    var routeMap = routeMapFromRoutes(routes);
    return {
      routes: Object.keys(routeMap).sort().map(function (key) { return routeMap[key]; }),
      routeMap: routeMap,
      warnings: warnings,
      vrfs: uniqueSorted(Object.keys(routeMap).map(function (key) { return routeMap[key].vrf; }))
    };
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

  function formatPath(path) {
    if (!path) return '-';
    if ((path.kind || '') === 'connected') return 'connected ' + (path.outInterface || '');
    if ((path.kind || '') === 'receive') return 'receive ' + (path.outInterface || '');
    if ((path.kind || '') === 'interface') return 'via ' + (path.outInterface || '-');
    return 'via ' + (path.nextHop || '-') + (path.outInterface ? ' ' + path.outInterface : '');
  }

  function formatRouteCode(route) {
    if (!route) return '-';
    if (route.isDefaultCandidate && route.routeType) return route.protocol + '*' + route.routeType;
    if (route.isDefaultCandidate) return route.protocol + '*';
    return route.protocol + (route.routeType ? ' ' + route.routeType : '');
  }

  function formatRoute(route) {
    if (!route) return '-';
    var code = formatRouteCode(route);
    var distance = route.adminDistance === null || route.metric === null ? '' : ' [' + route.adminDistance + '/' + route.metric + ']';
    var paths = route.paths && route.paths.length ? route.paths.map(formatPath).join('; ') : '-';
    return code + distance + ' ' + paths;
  }

  global.RouteDiffParser = {
    parse: parse,
    normalizeRoute: normalizeRoute,
    formatPath: formatPath,
    formatRouteCode: formatRouteCode,
    formatRoute: formatRoute,
    pathKey: pathKey,
    _internals: {
      stripAnsi: stripAnsi,
      parseRouteLine: parseRouteLine,
      parseContinuationLine: parseContinuationLine,
      parseRouteCode: parseRouteCode
    }
  };
}(window));
