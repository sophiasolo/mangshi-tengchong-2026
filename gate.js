/* gate.js — 访问口令 + 数据解密（无依赖）
 *
 * 部署版里 web/trip-data.json 不会上传，取而代之是 secure/trip-data.enc.json（AES-256-GCM 密文）。
 * 本脚本会在 app.js 取 trip-data.json 的时候拦截，先要口令，解密后再把明文交回去。
 * 本地预览（没有 secure/ 目录）时自动退化成「明文模式」，不影响开发。
 */
(function () {
  "use strict";

  var ENC_URL = "secure/trip-data.enc.json";
  var REMEMBER_KEY = "ms-trip-pass";
  var SESSION_KEY = "ms-trip-data";

  var originalFetch = window.fetch ? window.fetch.bind(window) : null;
  var mode = null;          // "enc" | "plain"
  var blob = null;          // 密文包
  var dataPromise = null;   // 解密后的数据
  var resolveData = null;

  /* ---------------- 工具 ---------------- */
  function b64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function deriveKey(pass, salt, iter) {
    var enc = new TextEncoder();
    return crypto.subtle
      .importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"])
      .then(function (base) {
        return crypto.subtle.deriveKey(
          { name: "PBKDF2", salt: salt, iterations: iter, hash: "SHA-256" },
          base,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );
      });
  }

  function decryptWith(pass) {
    return deriveKey(pass, b64ToBytes(blob.salt), blob.iter)
      .then(function (key) {
        return crypto.subtle.decrypt(
          { name: "AES-GCM", iv: b64ToBytes(blob.iv) },
          key,
          b64ToBytes(blob.ct)
        );
      })
      .then(function (plain) {
        return JSON.parse(new TextDecoder().decode(plain));
      });
  }

  /* ---------------- 口令界面 ---------------- */
  var CSS =
    ".gate{position:fixed;inset:0;z-index:9999;background:#0c222e;display:flex;align-items:center;justify-content:center;padding:24px;font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif}" +
    ".gate[hidden]{display:none}" +
    ".gate__box{width:100%;max-width:360px;color:#f2efe6}" +
    ".gate__kicker{font-size:11px;letter-spacing:.22em;color:#3fa79f;margin:0 0 10px}" +
    ".gate__title{font-size:26px;line-height:1.25;margin:0 0 6px;font-weight:800}" +
    ".gate__sub{font-size:13px;line-height:1.7;color:#9fb3bd;margin:0 0 22px}" +
    ".gate__input{width:100%;box-sizing:border-box;padding:14px 16px;border-radius:14px;border:1px solid #274a5c;background:#112b38;color:#f2efe6;font-size:17px;letter-spacing:.12em}" +
    ".gate__input:focus{outline:none;border-color:#3fa79f}" +
    ".gate__btn{width:100%;margin-top:14px;padding:15px;border:0;border-radius:14px;background:#3fa79f;color:#06222b;font-size:16px;font-weight:700;letter-spacing:.06em}" +
    ".gate__btn:disabled{opacity:.6}" +
    ".gate__remember{display:flex;align-items:center;gap:8px;margin-top:16px;font-size:13px;color:#9fb3bd}" +
    ".gate__err{min-height:20px;margin-top:12px;font-size:13px;color:#ff6b6b}" +
    ".gate__foot{margin-top:26px;font-size:11px;color:#5f7885;line-height:1.7}";

  function buildUI() {
    var style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);

    var wrap = document.createElement("div");
    wrap.className = "gate";
    wrap.id = "gate";
    wrap.innerHTML =
      '<div class="gate__box">' +
      '<p class="gate__kicker">PRIVATE TRAVEL PLAN</p>' +
      '<h1 class="gate__title">芒市 · 腾冲 · 保山</h1>' +
      '<p class="gate__sub">这是我们几个人的行程页，输入口令进入。</p>' +
      '<input class="gate__input" id="gate-pass" type="password" inputmode="text" autocomplete="current-password" placeholder="输入访问口令">' +
      '<button class="gate__btn" id="gate-btn" type="button">进入行程</button>' +
      '<label class="gate__remember"><input type="checkbox" id="gate-remember"> 这台手机记住，30 天内不用再输</label>' +
      '<p class="gate__err" id="gate-err"></p>' +
      '<p class="gate__foot">口令由发起人设定，只发给同行的人。忘记口令请找发起人要。</p>' +
      "</div>";
    document.body.appendChild(wrap);

    var input = wrap.querySelector("#gate-pass");
    var btn = wrap.querySelector("#gate-btn");
    var err = wrap.querySelector("#gate-err");
    var remember = wrap.querySelector("#gate-remember");

    function submit() {
      var pass = input.value.trim();
      if (!pass) {
        err.textContent = "请输入口令";
        return;
      }
      btn.disabled = true;
      btn.textContent = "解锁中…";
      err.textContent = "";
      decryptWith(pass)
        .then(function (plain) {
          try {
            sessionStorage.setItem(SESSION_KEY, JSON.stringify(plain));
          } catch (e) {}
          if (remember.checked) {
            try {
              localStorage.setItem(REMEMBER_KEY, pass);
            } catch (e) {}
          }
          finish(plain);
        })
        .catch(function () {
          btn.disabled = false;
          btn.textContent = "进入行程";
          err.textContent = "口令不对，再试一次";
          input.select();
        });
    }

    btn.addEventListener("click", submit);
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter") submit();
    });
    setTimeout(function () {
      input.focus();
    }, 120);
  }

  var uiShown = false;

  function finish(plain) {
    var gate = document.getElementById("gate");
    if (gate) gate.hidden = true;
    document.body.style.overflow = "";
    if (resolveData) {
      resolveData(plain);
      resolveData = null;
    }
  }

  /* ---------------- 取数主流程 ---------------- */
  function detectMode() {
    if (mode) return Promise.resolve(mode);
    return fetch(ENC_URL, { cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("no enc");
        return r.json();
      })
      .then(function (j) {
        blob = j;
        mode = "enc";
        return mode;
      })
      .catch(function () {
        mode = "plain";
        return mode;
      });
  }

  function getData() {
    if (dataPromise) return dataPromise;
    dataPromise = new Promise(function (resolve) {
      // 本标签页已经解锁过
      try {
        var cached = sessionStorage.getItem(SESSION_KEY);
        if (cached) {
          resolve(JSON.parse(cached));
          return;
        }
      } catch (e) {}

      resolveData = resolve;
      document.body.style.overflow = "hidden";
      if (!uiShown) {
        uiShown = true;
        if (document.readyState === "loading") {
          document.addEventListener("DOMContentLoaded", buildUI);
        } else {
          buildUI();
        }
      }
      // 记住过的设备自动解锁
      var saved = null;
      try {
        saved = localStorage.getItem(REMEMBER_KEY);
      } catch (e) {}
      if (saved) {
        decryptWith(saved)
          .then(function (plain) {
            try {
              sessionStorage.setItem(SESSION_KEY, JSON.stringify(plain));
            } catch (e) {}
            finish(plain);
          })
          .catch(function () {
            try {
              localStorage.removeItem(REMEMBER_KEY);
            } catch (e) {}
          });
      }
    });
    return dataPromise;
  }

  if (originalFetch) {
    window.fetch = function (input, init) {
      var url = typeof input === "string" ? input : (input && input.url) || "";
      if (url.indexOf("trip-data.json") === -1) return originalFetch(input, init);
      return detectMode().then(function (m) {
        if (m === "plain") return originalFetch(input, init);
        return getData().then(function (plain) {
          return new Response(JSON.stringify(plain), {
            status: 200,
            headers: { "Content-Type": "application/json; charset=utf-8" },
          });
        });
      });
    };
  }
})();
