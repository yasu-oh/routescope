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
  var AGE_TOKEN_RE = /^(?:\d{1,2}:\d{2}:\d{2}|\d+(?:\.\d+)?|\d+y\d+w|\d+w\d+d|\d+d\d+h|\d+h\d+m|\d+m\d+s|\d+[ywdhms])$/i;

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
    if (/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\s+\S+/i.test(trimmed)) return true;
    if (/^'\*+'\s+denotes\s/i.test(trimmed)) return true;
    if (/^'%<string>'\s+in\s+via\s+output\s+denotes\s+VRF/i.test(trimmed)) return true;
    if (/^'\[x\/y\]'\s+denotes\s+/i.test(trimmed)) return true;
    if (/^Route not found/i.test(trimmed)) return true;
    if (/^Route metric is\s+/i.test(trimmed)) return true;
    if (/^Tag\s+\d+/i.test(trimmed)) return true;
    if (/^Installed\s+/i.test(trimmed)) return true;
    if (/^Routing Descriptor Blocks\b/i.test(trimmed)) return true;
    if (/^No advertising protos\.?$/i.test(trimmed)) return true;
    if (/^%\s+(?:No matching routes found|Network not in table)/i.test(trimmed)) return true;
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
    match = line.match(/^\s*VRF:\s*(\S+)/i);
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

  function netmaskToPrefixLength(netmask) {
    var parts = String(netmask || '').split('.');
    if (parts.length !== 4) return null;
    var bits = '';
    for (var i = 0; i < parts.length; i += 1) {
      var octet = Number(parts[i]);
      if (octet < 0 || octet > 255 || isNaN(octet)) return null;
      bits += ('00000000' + octet.toString(2)).slice(-8);
    }
    if (!/^1*0*$/.test(bits)) return null;
    return bits.replace(/0+$/, '').length;
  }

  function normalizeNetworkAndMask(network, netmask) {
    var prefixLength = netmaskToPrefixLength(netmask);
    if (prefixLength === null) return String(network || '').trim() + ' ' + String(netmask || '').trim();
    return String(network || '').trim() + '/' + prefixLength;
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
          routeType = suffix.trim();
          protocol = protocol.slice(0, protocol.length - suffix.length).trim();
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
    return String(token || '').replace(/\s*\(!\)\s*/g, '').replace(/[(),]/g, '').trim();
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
      var rawPart = String(parts[i] || '').trim();
      if (/^\([^)]+\)$/.test(rawPart)) continue;
      var token = sanitizeToken(rawPart);
      if (looksLikeInterface(token)) {
        outInterface = token;
        break;
      }
    }
    if (!outInterface) {
      var nexthopVrf = tail.match(/\(nexthop\s+in\s+(vrf\s+[^)]+)\)/i);
      if (nexthopVrf) outInterface = sanitizeToken(nexthopVrf[1]);
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
    var match = String(rest || '').match(/is\s+directly\s+connected\s*(?:,\s*(.*))?$/i);
    if (!match) return null;
    var outInterface = '';
    var parts = String(match[1] || '').split(',');
    for (var i = parts.length - 1; i >= 0; i -= 1) {
      var token = sanitizeToken(parts[i]);
      if (looksLikeInterface(token)) {
        outInterface = token;
        break;
      }
    }
    return {
      nextHop: '',
      outInterface: outInterface,
      kind: 'connected'
    };
  }

  function pathKey(path) {
    return [path.kind || '', path.nextHop || '', path.outInterface || '', path.adminDistance === null || path.adminDistance === undefined ? '' : path.adminDistance, path.metric === null || path.metric === undefined ? '' : path.metric].join('|');
  }

  function annotatePath(path, adminDistance, metric) {
    if (!path) return path;
    if (adminDistance !== null && adminDistance !== undefined && adminDistance !== '') path.adminDistance = Number(adminDistance);
    if (metric !== null && metric !== undefined && metric !== '') path.metric = Number(metric);
    return path;
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
          kind: path.kind || (path.nextHop ? 'via' : 'connected'),
          adminDistance: path.adminDistance === undefined ? null : path.adminDistance,
          metric: path.metric === undefined ? null : path.metric
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
    route.key = [route.vrf, route.afi, route.prefix, route.protocol, route.routeType].join('|');
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

  function makeRouteFromParts(vrf, afi, prefix, protocolToken, routeTypeToken, adminDistance, metric, paths, rawLine) {
    var routeCode = parseRouteCode(protocolToken, routeTypeToken || '');
    return normalizeRoute({
      vrf: vrf || 'global',
      afi: afi || detectAfi(prefix),
      prefix: prefix,
      protocol: routeCode.protocol,
      routeType: routeCode.routeType,
      adminDistance: adminDistance === '' || adminDistance === null || adminDistance === undefined ? null : Number(adminDistance),
      metric: metric === '' || metric === null || metric === undefined ? null : Number(metric),
      isDefaultCandidate: routeCode.isDefaultCandidate,
      paths: paths || [],
      rawLines: [rawLine]
    });
  }

  function parsePathFromBareInterface(rest) {
    if (/\bvia\b/i.test(rest) || /directly\s+connected/i.test(rest)) return null;
    var match = String(rest || '').match(AD_METRIC_RE);
    if (!match) return null;
    var tail = String(rest || '').slice(String(rest || '').indexOf(match[0]) + match[0].length);
    var parts = tail.split(',');
    for (var i = parts.length - 1; i >= 0; i -= 1) {
      var token = sanitizeToken(parts[i]);
      if (looksLikeInterface(token)) return { nextHop: '', outInterface: token, kind: 'interface' };
    }
    return null;
  }

  function parsePathFromSummary(rest) {
    if (!/is\s+a\s+summary/i.test(rest)) return null;
    var parts = String(rest || '').split(',');
    for (var i = parts.length - 1; i >= 0; i -= 1) {
      var token = sanitizeToken(parts[i]);
      if (looksLikeInterface(token)) return { nextHop: '', outInterface: token, kind: 'summary' };
    }
    return null;
  }

  function parsePathFromVpn(rest) {
    var match = String(rest || '').match(/connected\s+by\s+VPN\s+\(advertised\),\s*(\S+)/i);
    if (!match) return null;
    return { nextHop: '', outInterface: sanitizeToken(match[1]), kind: 'vpn' };
  }

  function parseAsaNetmaskRoute(line, currentVrf) {
    var match = String(line || '').match(/^\s*([A-Za-z])(?:\s|\*)\s*([A-Za-z0-9]{0,2})\s+(\S+)\s+((?:\d{1,3}\.){3}\d{1,3})(.*)$/);
    if (!match) return null;
    var prefix = normalizeNetworkAndMask(match[3], match[4]);
    var rest = match[5] || '';
    var adMetric = parseAdMetric(rest);
    var connectedPath = parsePathFromConnected(rest);
    var viaPath = parsePathFromVia(rest);
    var barePath = parsePathFromBareInterface(rest);
    var summaryPath = parsePathFromSummary(rest);
    var vpnPath = parsePathFromVpn(rest);
    var path = connectedPath || viaPath || barePath || summaryPath || vpnPath;
    annotatePath(path, adMetric.adminDistance, adMetric.metric);
    return makeRouteFromParts(currentVrf, 'ipv4', prefix, match[1], match[2] || '', adMetric.adminDistance, adMetric.metric, path ? [path] : [], line.trim());
  }

  function parseVpnContinuation(line) {
    var match = String(line || '').match(/^\s*connected\s+by\s+VPN\s+\(advertised\),\s*(\S+)\s*$/i);
    if (!match) return null;
    return { nextHop: '', outInterface: sanitizeToken(match[1]), kind: 'vpn' };
  }

  function parseConnectedContinuation(line) {
    if (!/^\s+is\s+directly\s+connected/i.test(String(line || ''))) return null;
    var path = parsePathFromConnected(line);
    return path && path.outInterface ? path : null;
  }

  function parseNxosPrefixHeader(line) {
    var match = String(line || '').match(/^\s*((?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}),\s+ubest\/mbest:/i);
    return match ? match[1] : null;
  }

  function parseNxosRouteLine(line, currentVrf, pendingPrefix) {
    if (!pendingPrefix) return null;
    var match = String(line || '').match(/^\s*(?:\*+)?via\s+([^,]+)(?:,\s*([^\[,]+))?,\s*\[(\d+)\/(\d+)\],\s*([^,]+),\s*([^,\s]+)(?:,\s*([^,]+))?/i);
    if (!match) return null;
    var firstToken = sanitizeToken(match[1]);
    var outInterface = sanitizeToken(match[2] || '');
    var protocol = sanitizeToken(match[6]);
    var routeType = sanitizeToken(match[7] || '');
    if (/^tag\b/i.test(routeType)) routeType = '';
    if (/^discard$/i.test(routeType)) routeType = '';
    var nextHop = '';
    var vrfSplit = firstToken.split('%');
    firstToken = vrfSplit[0];
    if (isIpAddress(firstToken)) {
      nextHop = firstToken;
    } else if (!outInterface) {
      outInterface = firstToken;
    }
    var kind = nextHop ? 'via' : (/^Null/i.test(outInterface) ? 'discard' : 'interface');
    return makeRouteFromParts(currentVrf, 'ipv4', pendingPrefix, protocol, routeType, match[3], match[4], [annotatePath({ nextHop: nextHop, outInterface: outInterface, kind: kind }, match[3], match[4])], line.trim());
  }

  function parseXrRouteEntryHeader(line) {
    var match = String(line || '').match(/^\s*Routing\s+entry\s+for\s+((?:\d{1,3}\.){3}\d{1,3}\/\d{1,2})/i);
    return match ? match[1] : null;
  }

  function parseXrKnownVia(line) {
    var match = String(line || '').match(/^\s*Known\s+via\s+"([^"]+)",\s+distance\s+(\d+),\s+metric\s+(\d+)/i);
    if (!match) return null;
    return { protocol: match[1], adminDistance: Number(match[2]), metric: Number(match[3]) };
  }

  function parseXrDescriptorPath(line, currentVrf, xrEntry) {
    if (!xrEntry || !xrEntry.prefix) return null;
    var match = String(line || '').match(/^\s*((?:\d{1,3}\.){3}\d{1,3})(?:,\s+from\s+\S+)?(?:,\s+via\s+(\S+))?\s*$/i);
    if (!match) return null;
    var nextHop = match[1];
    var outInterface = sanitizeToken(match[2] || '');
    return makeRouteFromParts(currentVrf, 'ipv4', xrEntry.prefix, xrEntry.protocol || '', '', xrEntry.adminDistance, xrEntry.metric, [annotatePath({ nextHop: nextHop, outInterface: outInterface, kind: 'via' }, xrEntry.adminDistance, xrEntry.metric)], line.trim());
  }

  function makeRoute(vrf, protocolToken, routeTypeToken, prefix, rest, rawLine, inheritedPrefixLength) {
    var adMetric = parseAdMetric(rest);
    var routeCode = parseRouteCode(protocolToken, routeTypeToken);
    var connectedPath = parsePathFromConnected(rest);
    var viaPath = parsePathFromVia(rest);
    var barePath = parsePathFromBareInterface(rest);
    var summaryPath = parsePathFromSummary(rest);
    annotatePath(connectedPath, adMetric.adminDistance, adMetric.metric);
    annotatePath(viaPath, adMetric.adminDistance, adMetric.metric);
    annotatePath(barePath, adMetric.adminDistance, adMetric.metric);
    annotatePath(summaryPath, adMetric.adminDistance, adMetric.metric);
    return normalizeRoute({
      vrf: vrf || 'global',
      afi: detectAfi(prefix),
      prefix: normalizePrefix(prefix, inheritedPrefixLength),
      protocol: routeCode.protocol,
      routeType: routeCode.routeType,
      adminDistance: adMetric.adminDistance,
      metric: adMetric.metric,
      isDefaultCandidate: routeCode.isDefaultCandidate,
      paths: connectedPath ? [connectedPath] : (viaPath ? [viaPath] : (barePath ? [barePath] : (summaryPath ? [summaryPath] : []))),
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
    annotatePath(path, match[1] ? Number(match[1]) : null, match[2] ? Number(match[2]) : null);
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
    var pendingNxosPrefix = null;
    var xrEntry = null;
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
        pendingNxosPrefix = null;
        xrEntry = null;
        continue;
      }
      var headerVrf = parseVrfHeader(line);
      if (headerVrf) {
        currentVrf = headerVrf;
        lastRoute = null;
        inheritedPrefixLength = null;
        pendingNxosPrefix = null;
        xrEntry = null;
        continue;
      }
      var xrPrefix = parseXrRouteEntryHeader(line);
      if (xrPrefix) {
        xrEntry = { prefix: xrPrefix, protocol: '', adminDistance: null, metric: null };
        lastRoute = null;
        continue;
      }
      var xrKnown = parseXrKnownVia(line);
      if (xrKnown && xrEntry) {
        xrEntry.protocol = xrKnown.protocol;
        xrEntry.adminDistance = xrKnown.adminDistance;
        xrEntry.metric = xrKnown.metric;
        continue;
      }
      var nxosPrefix = parseNxosPrefixHeader(line);
      if (nxosPrefix) {
        pendingNxosPrefix = nxosPrefix;
        lastRoute = null;
        xrEntry = null;
        continue;
      }
      var subnetPrefixLength = parseSubnetHeader(line);
      if (subnetPrefixLength !== null) {
        inheritedPrefixLength = subnetPrefixLength;
        lastRoute = null;
        continue;
      }
      if (isIgnorableLine(line)) continue;

      var xrDescriptorRoute = parseXrDescriptorPath(line, currentVrf, xrEntry);
      if (xrDescriptorRoute) {
        routes.push(xrDescriptorRoute);
        lastRoute = xrDescriptorRoute;
        continue;
      }

      var nxosRoute = parseNxosRouteLine(line, currentVrf, pendingNxosPrefix);
      if (nxosRoute) {
        routes.push(nxosRoute);
        lastRoute = nxosRoute;
        continue;
      }

      var asaRoute = parseAsaNetmaskRoute(line, currentVrf);
      if (asaRoute) {
        routes.push(asaRoute);
        lastRoute = asaRoute;
        continue;
      }

      var vpnPath = parseVpnContinuation(line);
      if (vpnPath) {
        if (!lastRoute) {
          warnings.push({ line: lineNumber, message: 'VPN continuation without previous prefix', content: line.trim() });
          continue;
        }
        lastRoute.rawLines.push(line.trim());
        lastRoute.paths.push(vpnPath);
        normalizeRoute(lastRoute);
        continue;
      }

      var connectedContinuation = parseConnectedContinuation(line);
      if (connectedContinuation) {
        if (!lastRoute) {
          warnings.push({ line: lineNumber, message: 'Connected continuation without previous prefix', content: line.trim() });
          continue;
        }
        lastRoute.rawLines.push(line.trim());
        lastRoute.paths.push(connectedContinuation);
        normalizeRoute(lastRoute);
        continue;
      }

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
    if ((path.kind || '') === 'vpn') return 'VPN ' + (path.outInterface || '');
    if ((path.kind || '') === 'discard') return 'discard ' + (path.outInterface || '');
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
