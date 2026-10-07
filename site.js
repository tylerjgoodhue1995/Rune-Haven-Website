(() => {
  "use strict";
  const KEY = "rh-session";
  const NAV = [["/", "Home"], ["/dashboard.html", "Dashboard"], ["/market.html", "Marketplace"], ["/news.html", "News"]];
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  const $ = (selector, root = document) => root.querySelector(selector);
  const esc = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const short = (wallet) => (wallet && wallet.length > 12 ? `${wallet.slice(0, 4)}…${wallet.slice(-4)}` : wallet || "");

  const session = () => { try { return JSON.parse(sessionStorage.getItem(KEY)); } catch { return null; } };
  const setSession = (value) => (value ? sessionStorage.setItem(KEY, JSON.stringify(value)) : sessionStorage.removeItem(KEY));

  async function api(path, options = {}) {
    const headers = { "content-type": "application/json" };
    const current = session();
    if (options.auth !== false && current) headers.authorization = `Bearer ${current.token}`;
    const response = await fetch(path, {
      method: options.method || (options.body ? "POST" : "GET"),
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401 && current) setSession(null);
    if (!response.ok) throw new Error(data.message || `Request failed (${response.status})`);
    return data;
  }

  function b58(bytes) {
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    let out = "";
    while (value > 0n) { out = ALPHABET[Number(value % 58n)] + out; value /= 58n; }
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    return "1".repeat(zeros) + out;
  }

  const provider = () => window.phantom?.solana || window.solana;

  async function signIn() {
    const phantom = provider();
    if (!phantom?.isPhantom) throw new Error("Phantom was not detected. Install the wallet extension and reload.");
    const { publicKey } = await phantom.connect();
    const wallet = publicKey.toString();
    const challenge = await api("/api/v1/auth/challenge", { body: { wallet }, auth: false });
    const signed = await phantom.signMessage(new TextEncoder().encode(challenge.message), "utf8");
    const result = await api("/api/v1/auth/verify", { body: { wallet, nonce: challenge.nonce, signature: b58(signed.signature) }, auth: false });
    setSession({ token: result.token, wallet: result.wallet, alpha_access: result.alpha_access, is_admin: result.is_admin });
    return session();
  }

  function toast(text) {
    let node = $("#toast");
    if (!node) {
      node = document.createElement("div");
      node.id = "toast";
      node.setAttribute("role", "status");
      node.style.cssText = "position:fixed;right:18px;bottom:18px;max-width:340px;padding:12px 16px;border-radius:6px;background:#2a2630;border:1px solid rgba(228,189,112,.4);color:#f5efe3;font:13px system-ui,sans-serif;z-index:9";
      document.body.appendChild(node);
    }
    node.textContent = text;
    node.hidden = false;
    clearTimeout(node.timer);
    node.timer = setTimeout(() => { node.hidden = true; }, 6000);
  }

  function shell(active) {
    const current = session();
    const links = NAV.map(([href, label]) => `<a href="${href}"${href === active ? ' aria-current="page"' : ""}>${label}</a>`);
    if (current?.is_admin) links.push(`<a href="/admin.html"${active === "/admin.html" ? ' aria-current="page"' : ""}>Admin</a>`);
    const account = current
      ? `<span class="account"><code>${esc(short(current.wallet))}</code><button class="btn quiet" id="signout" type="button">Sign out</button></span>`
      : '<button class="btn" id="signin" type="button">Connect Phantom</button>';
    $("#top").innerHTML = `<a class="brand" href="/"><img src="/assets/rune-haven-logo.png" alt=""><span class="brand-title">Rune Haven</span></a><nav class="links" aria-label="Main">${links.join("")}</nav>${account}`;
    $("#bottom").innerHTML = '<span>© Rune Haven · Alpha on Solana</span><span><a href="/news.html">News</a> · <a href="https://github.com/tylerjgoodhue1995/Rune-Haven/releases" target="_blank" rel="noopener">Game updates</a></span>';
    if (!$(".embers") && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      const layer = document.createElement("div");
      layer.className = "embers";
      layer.setAttribute("aria-hidden", "true");
      for (let i = 0; i < 26; i++) {
        const ember = document.createElement("i");
        ember.style.cssText = `left:${Math.random() * 100}%;--s:${(2 + Math.random() * 4).toFixed(1)}px;--d:${(14 + Math.random() * 18).toFixed(1)}s;--delay:-${(Math.random() * 30).toFixed(1)}s;--x:${(Math.random() * 120 - 60).toFixed(0)}px`;
        layer.appendChild(ember);
      }
      document.body.prepend(layer);
    }
    $("#signin")?.addEventListener("click", async (event) => {
      event.target.disabled = true;
      try { await signIn(); location.reload(); } catch (error) { toast(error.message); event.target.disabled = false; }
    });
    $("#signout")?.addEventListener("click", () => { setSession(null); location.href = "/"; });
  }

  function guard() {
    if (session()) return true;
    document.body.classList.add("need-signin");
    return false;
  }

  function setMsg(node, text, kind = "") { node.textContent = text; node.dataset.kind = kind; }

  function fmtUnits(baseUnits, decimals) {
    const raw = BigInt(baseUnits || "0");
    const scale = 10n ** BigInt(decimals || 0);
    const whole = raw / scale;
    const frac = (raw % scale).toString().padStart(Number(decimals || 0), "0").replace(/0+$/, "");
    return frac ? `${whole.toLocaleString()}.${frac}` : whole.toLocaleString();
  }

  function prettyItem(id) {
    const parts = String(id).split(".").slice(-2);
    return parts.join(" ").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }

  window.RH = { $, esc, short, session, api, signIn, shell, guard, toast, setMsg, fmtUnits, prettyItem, b58, provider };
})();
