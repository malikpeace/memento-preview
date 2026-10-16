// Web Memento's private preview (scripts/lock-web.mjs builds it). The app's script is stored encrypted (AES-GCM with a
// key made from the passcode by PBKDF2), so the published files show nothing of Memento without the passcode. This asks
// for it, decrypts the script in the browser and starts it. The key, never the passcode, is remembered on this device,
// so the next visit opens straight away; a wrong or changed passcode asks again.
(function () {
  var me = document.currentScript;
  var APP = me.getAttribute('data-app'), SALT = me.getAttribute('data-salt'), ITER = Number(me.getAttribute('data-iter'));
  var KEY = 'memento.preview-key.v1';
  var gate = document.getElementById('gate'), boot = document.getElementById('boot');
  var field = document.getElementById('gate-code'), button = document.getElementById('gate-open'), note = document.getElementById('gate-note');
  var sealed = null;

  function bytes(b64) { var s = atob(b64), out = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }
  function b64(buf) { var s = '', a = new Uint8Array(buf); for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function remember(raw) { try { localStorage.setItem(KEY, raw); } catch (e) { /* private mode: ask again next time */ } }
  function remembered() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function forget() { try { localStorage.removeItem(KEY); } catch (e) { /* nothing stored */ } }

  // The launch screen's hairline (public/index.html): the app's download fills most of it, starting fills the rest.
  var bar = document.getElementById('boot-bar');
  function progress(p) {
    if (!bar) return;
    boot.classList.add('boot-progress');
    bar.style.transform = 'scaleX(' + Math.max(0, Math.min(1, p)) + ')';
  }

  function fetchApp() {
    if (sealed) return Promise.resolve(sealed);
    return fetch(APP, { cache: 'force-cache' }).then(function (r) {
      if (!r.ok) throw new Error('fetch');
      var total = Number(r.headers.get('content-length')) || 0;
      if (!r.body || !total) return r.arrayBuffer();
      var reader = r.body.getReader(), parts = [], got = 0;
      function pump() {
        return reader.read().then(function (step) {
          if (step.done) { var out = new Uint8Array(got), at = 0; parts.forEach(function (c) { out.set(c, at); at += c.length; }); return out.buffer; }
          parts.push(step.value); got += step.value.length; progress(0.85 * got / total);
          return pump();
        });
      }
      return pump();
    }).then(function (buf) { sealed = new Uint8Array(buf); return sealed; });
  }
  // The app's script is gzipped before it is encrypted (encrypted bytes do not compress in transit), so it is
  // unpacked here after decryption.
  function gunzip(buf) {
    return new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
  }
  function keyFrom(code) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(code), 'PBKDF2', false, ['deriveKey']).then(function (base) {
      return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: bytes(SALT), iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
    });
  }
  // Decrypts and starts the app. Rejects with 'wrong' for a key that does not open it, 'load' for a network failure.
  function start(key) {
    return fetchApp().catch(function () { throw 'load'; }).then(function (data) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12)).catch(function () { throw 'wrong'; });
    }).then(gunzip).then(function (js) {
      gate.hidden = true;
      boot.style.display = '';
      progress(0.95);
      var s = document.createElement('script');
      s.src = URL.createObjectURL(new Blob([js], { type: 'text/javascript' }));
      document.body.appendChild(s);
    });
  }
  function ask(message) {
    fetchApp().catch(function () { /* retried on submit */ });   // download while the passcode is typed
    boot.style.display = 'none';
    gate.hidden = false;
    note.textContent = message || '';
    button.disabled = false; button.textContent = 'Open';
    field.focus();
  }

  gate.addEventListener('submit', function (e) {
    e.preventDefault();
    var code = field.value.trim().toLowerCase();
    if (!code) return;
    button.disabled = true; button.textContent = 'Opening…'; note.textContent = '';
    keyFrom(code).then(function (key) {
      return start(key).then(function () { return crypto.subtle.exportKey('raw', key); }).then(function (raw) { remember(b64(raw)); });
    }).catch(function (why) {
      field.select();
      ask(why === 'load' ? 'Memento could not load. Check your connection and try again.' : 'That passcode is not right.');
    });
  });

  if (typeof DecompressionStream === 'undefined') { ask('This browser is too old for Memento. Update it and try again.'); button.disabled = true; return; }
  var raw = remembered();
  if (!raw) { ask(); return; }
  crypto.subtle.importKey('raw', bytes(raw), { name: 'AES-GCM' }, false, ['decrypt']).then(start).catch(function (why) {
    if (why !== 'load') forget();
    ask(why === 'load' ? 'Memento could not load. Check your connection and try again.' : '');
  });
})();
