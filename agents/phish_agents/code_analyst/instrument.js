// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// Injected by the code analyst before page scripts run. Records who listens to
// keystrokes and where data is sent, which static source reading can miss when
// the code is obfuscated or loaded late.
(() => {
  const log = { listeners: [], sinks: [] };
  Object.defineProperty(window, "__phishLog", {
    value: log,
    enumerable: false,
  });
  const watched = new Set([
    "keydown",
    "keyup",
    "keypress",
    "input",
    "change",
    "paste",
    "copy",
    "submit",
  ]);
  const describe = (t) => {
    if (t === window) return "window";
    if (t === document) return "document";
    return t && t.tagName
      ? t.tagName.toLowerCase() + (t.type ? "[" + t.type + "]" : "")
      : String(t).slice(0, 80);
  };
  const seen = new Set();
  const record = (type, target, via) => {
    const entry = { type, target: describe(target), via };
    const key = entry.type + "|" + entry.target + "|" + via;
    if (seen.has(key) || log.listeners.length >= 200) return;
    seen.add(key);
    log.listeners.push(entry);
  };
  const origAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, fn, opts) {
    if (watched.has(type)) record(type, this, "listener");
    return origAdd.call(this, type, fn, opts);
  };
  // `el.onkeydown = fn` never calls addEventListener, so wrap the on* setters too.
  // Window attributes live on the window object itself, the others on prototypes.
  for (const holder of [HTMLElement.prototype, Document.prototype, window]) {
    for (const type of watched) {
      const prop = "on" + type;
      const desc = Object.getOwnPropertyDescriptor(holder, prop);
      if (!desc || !desc.set || !desc.configurable) continue;
      Object.defineProperty(holder, prop, {
        ...desc,
        set(fn) {
          if (typeof fn === "function") record(type, this, "property");
          return desc.set.call(this, fn);
        },
      });
    }
  }
  // Inline onkeydown="..." attributes, both parsed from HTML and set later by script.
  const origSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    const lower = String(name).toLowerCase();
    if (lower.startsWith("on") && watched.has(lower.slice(2)))
      record(lower.slice(2), this, "attribute");
    return origSetAttr.call(this, name, value);
  };
  const selector = [...watched].map((t) => "[on" + t + "]").join(",");
  Object.defineProperty(window, "__phishCollect", {
    value: () => {
      for (const el of document.querySelectorAll(selector))
        for (const type of watched)
          if (el.hasAttribute("on" + type)) record(type, el, "attribute");
      for (const target of [document.documentElement, document.body])
        for (const type of watched)
          if (target && target.hasAttribute("on" + type))
            record(type, target, "attribute");
    },
    enumerable: false,
  });
  const sink = (kind, url) => {
    if (log.sinks.length < 200)
      log.sinks.push({ kind, url: String(url).slice(0, 300) });
  };
  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    sink("fetch", input && input.url ? input.url : input);
    return origFetch.call(this, input, init);
  };
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    sink("xhr", url);
    return origOpen.apply(this, arguments);
  };
  if (navigator.sendBeacon) {
    const origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = (url, data) => {
      sink("beacon", url);
      return origBeacon(url, data);
    };
  }
  const OrigWS = window.WebSocket;
  if (typeof OrigWS === "function") {
    // Page code reads WebSocket.OPEN and friends and checks instanceof, so the wrapper
    // keeps the original prototype and its static readyState constants.
    const WrappedWS = function WebSocket(url, protocols) {
      sink("websocket", url);
      return new OrigWS(url, protocols);
    };
    WrappedWS.prototype = OrigWS.prototype;
    for (const name of ["CONNECTING", "OPEN", "CLOSING", "CLOSED"]) {
      const desc = Object.getOwnPropertyDescriptor(OrigWS, name);
      if (desc) Object.defineProperty(WrappedWS, name, desc);
    }
    Object.setPrototypeOf(WrappedWS, Object.getPrototypeOf(OrigWS));
    window.WebSocket = WrappedWS;
  }
})();
