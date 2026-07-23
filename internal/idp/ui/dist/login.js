//#region node_modules/solid-js/dist/solid.js
var e = {
	context: void 0,
	registry: void 0,
	effects: void 0,
	done: !1,
	getContextId() {
		return t(this.context.count);
	},
	getNextContextId() {
		return t(this.context.count++);
	}
};
function t(t) {
	let n = String(t), r = n.length - 1;
	return e.context.id + (r ? String.fromCharCode(96 + r) : "") + n;
}
var n = (e, t) => e === t, r = Symbol("solid-proxy"), i = typeof Proxy == "function", a = { equals: n }, o = null, s = k, c = 1, l = 2, u = {
	owned: null,
	cleanups: null,
	context: null,
	owner: null
}, d = null, f = null, p = null, m = null, h = null, g = 0;
function ee(e, t) {
	let n = p, r = d, i = e.length === 0, a = t === void 0 ? r : t, o = i ? u : {
		owned: null,
		cleanups: null,
		context: a ? a.context : null,
		owner: a
	}, s = i ? e : () => e(() => b(() => M(o)));
	d = o, p = null;
	try {
		return O(s, !0);
	} finally {
		p = n, d = r;
	}
}
function _(e, t) {
	t = t ? Object.assign({}, a, t) : a;
	let n = {
		value: e,
		observers: null,
		observerSlots: null,
		comparator: t.equals || void 0
	};
	return [S.bind(n), (e) => (typeof e == "function" && (e = f && f.running && f.sources.has(n) ? e(n.tValue) : e(n.value)), C(n, e))];
}
function v(e, t, n) {
	w(E(e, t, !1, c));
}
function y(e, t, n) {
	n = n ? Object.assign({}, a, n) : a;
	let r = E(e, t, !0, 0);
	return r.observers = null, r.observerSlots = null, r.comparator = n.equals || void 0, w(r), S.bind(r);
}
function b(e) {
	if (p === null) return e();
	let t = p;
	p = null;
	try {
		return e();
	} finally {
		p = t;
	}
}
var [te, x] = /*@__PURE__*/ _(!1);
function S() {
	let e = f && f.running;
	if (this.sources && (e ? this.tState : this.state)) if ((e ? this.tState : this.state) === c) w(this);
	else {
		let e = m;
		m = null, O(() => A(this), !1), m = e;
	}
	if (p) {
		let e = this.observers;
		if (!e || e[e.length - 1] !== p) {
			let t = e ? e.length : 0;
			p.sources ? (p.sources.push(this), p.sourceSlots.push(t)) : (p.sources = [this], p.sourceSlots = [t]), e ? (e.push(p), this.observerSlots.push(p.sources.length - 1)) : (this.observers = [p], this.observerSlots = [p.sources.length - 1]);
		}
	}
	return e && f.sources.has(this) ? this.tValue : this.value;
}
function C(e, t, n) {
	let r = f && f.running && f.sources.has(e) ? e.tValue : e.value;
	if (!e.comparator || !e.comparator(r, t)) {
		if (f) {
			let r = f.running;
			(r || !n && f.sources.has(e)) && (f.sources.add(e), e.tValue = t), r || (e.value = t);
		} else e.value = t;
		e.observers && e.observers.length && O(() => {
			for (let t = 0; t < e.observers.length; t += 1) {
				let n = e.observers[t], r = f && f.running;
				r && f.disposed.has(n) || ((r ? !n.tState : !n.state) && (n.pure ? m.push(n) : h.push(n), n.observers && j(n)), r ? n.tState = c : n.state = c);
			}
			if (m.length > 1e6) throw m = [], Error();
		}, !1);
	}
	return t;
}
function w(e) {
	if (!e.fn) return;
	M(e);
	let t = g;
	T(e, f && f.running && f.sources.has(e) ? e.tValue : e.value, t), f && !f.running && f.sources.has(e) && queueMicrotask(() => {
		O(() => {
			f && (f.running = !0), p = d = e, T(e, e.tValue, t), p = d = null;
		}, !1);
	});
}
function T(e, t, n) {
	let r, i = d, a = p;
	p = d = e;
	try {
		r = e.fn(t);
	} catch (t) {
		return e.pure && (f && f.running ? (e.tState = c, e.tOwned && e.tOwned.forEach(M), e.tOwned = void 0) : (e.state = c, e.owned && e.owned.forEach(M), e.owned = null)), e.updatedAt = n + 1, I(t);
	} finally {
		p = a, d = i;
	}
	(!e.updatedAt || e.updatedAt <= n) && (e.updatedAt != null && "observers" in e ? C(e, r, !0) : f && f.running && e.pure ? (f.sources.has(e) || (e.value = r), f.sources.add(e), e.tValue = r) : e.value = r, e.updatedAt = n);
}
function E(e, t, n, r = c, i) {
	let a = {
		fn: e,
		state: r,
		updatedAt: null,
		owned: null,
		sources: null,
		sourceSlots: null,
		cleanups: null,
		value: t,
		owner: d,
		context: d ? d.context : null,
		pure: n
	};
	return f && f.running && (a.state = 0, a.tState = r), d === null || d !== u && (f && f.running && d.pure ? d.tOwned ? d.tOwned.push(a) : d.tOwned = [a] : d.owned ? d.owned.push(a) : d.owned = [a]), a;
}
function D(e) {
	let t = f && f.running;
	if ((t ? e.tState : e.state) === 0) return;
	if ((t ? e.tState : e.state) === l) return A(e);
	if (e.suspense && b(e.suspense.inFallback)) return e.suspense.effects.push(e);
	let n = [e];
	for (; (e = e.owner) && (!e.updatedAt || e.updatedAt < g);) {
		if (t && f.disposed.has(e)) return;
		(t ? e.tState : e.state) && n.push(e);
	}
	for (let r = n.length - 1; r >= 0; r--) {
		if (e = n[r], t) {
			let t = e, i = n[r + 1];
			for (; (t = t.owner) && t !== i;) if (f.disposed.has(t)) return;
		}
		if ((t ? e.tState : e.state) === c) w(e);
		else if ((t ? e.tState : e.state) === l) {
			let t = m;
			m = null, O(() => A(e, n[0]), !1), m = t;
		}
	}
}
function O(e, t) {
	if (m) return e();
	let n = !1;
	t || (m = []), h ? n = !0 : h = [], g++;
	try {
		let t = e();
		return ne(n), t;
	} catch (e) {
		n || (h = null), m = null, I(e);
	}
}
function ne(e) {
	if (m &&= (k(m), null), e) return;
	let t;
	if (f) {
		if (!f.promises.size && !f.queue.size) {
			let e = f.sources, n = f.disposed;
			h.push.apply(h, f.effects), t = f.resolve;
			for (let e of h) "tState" in e && (e.state = e.tState), delete e.tState;
			f = null, O(() => {
				for (let e of n) M(e);
				for (let t of e) {
					if (t.value = t.tValue, t.owned) for (let e = 0, n = t.owned.length; e < n; e++) M(t.owned[e]);
					t.tOwned && (t.owned = t.tOwned), delete t.tValue, delete t.tOwned, t.tState = 0;
				}
				x(!1);
			}, !1);
		} else if (f.running) {
			f.running = !1, f.effects.push.apply(f.effects, h), h = null, x(!0);
			return;
		}
	}
	let n = h;
	h = null, n.length && O(() => s(n), !1), t && t();
}
function k(e) {
	for (let t = 0; t < e.length; t++) D(e[t]);
}
function A(e, t) {
	let n = f && f.running;
	n ? e.tState = 0 : e.state = 0;
	for (let r = 0; r < e.sources.length; r += 1) {
		let i = e.sources[r];
		if (i.sources) {
			let e = n ? i.tState : i.state;
			e === c ? i !== t && (!i.updatedAt || i.updatedAt < g) && D(i) : e === l && A(i, t);
		}
	}
}
function j(e) {
	let t = f && f.running;
	for (let n = 0; n < e.observers.length; n += 1) {
		let r = e.observers[n];
		(t ? !r.tState : !r.state) && (t ? r.tState = l : r.state = l, r.pure ? m.push(r) : h.push(r), r.observers && j(r));
	}
}
function M(e) {
	let t;
	if (e.sources) for (; e.sources.length;) {
		let t = e.sources.pop(), n = e.sourceSlots.pop(), r = t.observers;
		if (r && r.length) {
			let e = r.pop(), i = t.observerSlots.pop();
			n < r.length && (e.sourceSlots[i] = n, r[n] = e, t.observerSlots[n] = i);
		}
	}
	if (e.tOwned) {
		for (t = e.tOwned.length - 1; t >= 0; t--) M(e.tOwned[t]);
		delete e.tOwned;
	}
	if (f && f.running && e.pure) N(e, !0);
	else if (e.owned) {
		for (t = e.owned.length - 1; t >= 0; t--) M(e.owned[t]);
		e.owned = null;
	}
	if (e.cleanups) {
		for (t = e.cleanups.length - 1; t >= 0; t--) e.cleanups[t]();
		e.cleanups = null;
	}
	f && f.running ? e.tState = 0 : e.state = 0;
}
function N(e, t) {
	if (t || (e.tState = 0, f.disposed.add(e)), e.owned) for (let t = 0; t < e.owned.length; t++) N(e.owned[t]);
}
function P(e) {
	return e instanceof Error ? e : Error(typeof e == "string" ? e : "Unknown error", { cause: e });
}
function F(e, t, n) {
	try {
		for (let n of t) n(e);
	} catch (e) {
		I(e, n && n.owner || null);
	}
}
function I(e, t = d) {
	let n = o && t && t.context && t.context[o], r = P(e);
	if (!n) throw r;
	h ? h.push({
		fn() {
			F(r, n, t);
		},
		state: c
	}) : F(r, n, t);
}
function L(e, t) {
	return b(() => e(t || {}));
}
function R() {
	return !0;
}
var z = {
	get(e, t, n) {
		return t === r ? n : e.get(t);
	},
	has(e, t) {
		return t === r || e.has(t);
	},
	set: R,
	deleteProperty: R,
	getOwnPropertyDescriptor(e, t) {
		return {
			configurable: !0,
			enumerable: !0,
			get() {
				return e.get(t);
			},
			set: R,
			deleteProperty: R
		};
	},
	ownKeys(e) {
		return e.keys();
	}
};
function B(e) {
	return (e = typeof e == "function" ? e() : e) ? e : {};
}
function V() {
	for (let e = 0, t = this.length; e < t; ++e) {
		let t = this[e]();
		if (t !== void 0) return t;
	}
}
function H(...e) {
	let t = !1;
	for (let n = 0; n < e.length; n++) {
		let i = e[n];
		t ||= !!i && r in i, e[n] = typeof i == "function" ? (t = !0, y(i)) : i;
	}
	if (i && t) return new Proxy({
		get(t) {
			for (let n = e.length - 1; n >= 0; n--) {
				let r = B(e[n])[t];
				if (r !== void 0) return r;
			}
		},
		has(t) {
			for (let n = e.length - 1; n >= 0; n--) if (t in B(e[n])) return !0;
			return !1;
		},
		keys() {
			let t = [];
			for (let n = 0; n < e.length; n++) t.push(...Object.keys(B(e[n])));
			return [...new Set(t)];
		}
	}, z);
	let n = {}, a = Object.create(null);
	for (let t = e.length - 1; t >= 0; t--) {
		let r = e[t];
		if (!r) continue;
		let i = Object.getOwnPropertyNames(r);
		for (let e = i.length - 1; e >= 0; e--) {
			let t = i[e];
			if (t === "__proto__" || t === "constructor") continue;
			let o = Object.getOwnPropertyDescriptor(r, t);
			if (!a[t]) a[t] = o.get ? {
				enumerable: !0,
				configurable: !0,
				get: V.bind(n[t] = [o.get.bind(r)])
			} : o.value === void 0 ? void 0 : o;
			else {
				let e = n[t];
				e && (o.get ? e.push(o.get.bind(r)) : o.value !== void 0 && e.push(() => o.value));
			}
		}
	}
	let o = {}, s = Object.keys(a);
	for (let e = s.length - 1; e >= 0; e--) {
		let t = s[e], n = a[t];
		n && n.get ? Object.defineProperty(o, t, n) : o[t] = n ? n.value : void 0;
	}
	return o;
}
var U = (e) => `Stale read from <${e}>.`;
function W(e) {
	let t = e.keyed, n = y(() => e.when, void 0, void 0), r = t ? n : y(n, void 0, { equals: (e, t) => !e == !t });
	return y(() => {
		let i = r();
		if (i) {
			let a = e.children;
			return typeof a == "function" && a.length > 0 ? b(() => a(t ? i : () => {
				if (!b(r)) throw U("Show");
				return n();
			})) : a;
		}
		return e.fallback;
	}, void 0, void 0);
}
//#endregion
//#region node_modules/solid-js/web/dist/web.js
var re = (e) => y(() => e());
function ie(e, t, n) {
	let r = n.length, i = t.length, a = r, o = 0, s = 0, c = t[i - 1].nextSibling, l = null;
	for (; o < i || s < a;) {
		if (t[o] === n[s]) {
			o++, s++;
			continue;
		}
		for (; t[i - 1] === n[a - 1];) i--, a--;
		if (i === o) {
			let t = a < r ? s ? n[s - 1].nextSibling : n[a - s] : c;
			for (; s < a;) e.insertBefore(n[s++], t);
		} else if (a === s) for (; o < i;) (!l || !l.has(t[o])) && t[o].remove(), o++;
		else if (t[o] === n[a - 1] && n[s] === t[i - 1]) {
			let r = t[--i].nextSibling;
			e.insertBefore(n[s++], t[o++].nextSibling), e.insertBefore(n[--a], r), t[i] = n[a];
		} else {
			if (!l) {
				l = /* @__PURE__ */ new Map();
				let e = s;
				for (; e < a;) l.set(n[e], e++);
			}
			let r = l.get(t[o]);
			if (r != null) if (s < r && r < a) {
				let c = o, u = 1, d;
				for (; ++c < i && c < a && !((d = l.get(t[c])) == null || d !== r + u);) u++;
				if (u > r - s) {
					let i = t[o];
					for (; s < r;) e.insertBefore(n[s++], i);
				} else e.replaceChild(n[s++], t[o++]);
			} else o++;
			else t[o++].remove();
		}
	}
}
function ae(e, t, n, r = {}) {
	let i;
	return ee((r) => {
		i = r, t === document ? e() : q(t, e(), t.firstChild ? null : void 0, n);
	}, r.owner), () => {
		i(), t.textContent = "";
	};
}
function G(e, t, n, r) {
	let i, a = () => {
		let t = r ? document.createElementNS("http://www.w3.org/1998/Math/MathML", "template") : document.createElement("template");
		return t.innerHTML = e, n ? t.content.firstChild.firstChild : r ? t.firstChild : t.content.firstChild;
	}, o = t ? () => b(() => document.importNode(i ||= a(), !0)) : () => (i ||= a()).cloneNode(!0);
	return o.cloneNode = o, o;
}
function K(e, t, n) {
	J(e) || (n == null ? e.removeAttribute(t) : e.setAttribute(t, n));
}
function q(e, t, n, r) {
	if (n !== void 0 && !r && (r = []), typeof t != "function") return Y(e, t, r, n);
	v((r) => Y(e, t(), r, n), r);
}
function J(t) {
	return !!e.context && !e.done && (!t || t.isConnected);
}
function Y(e, t, n, r, i) {
	let a = J(e);
	if (a) {
		!n && (n = [...e.childNodes]);
		let t = [];
		for (let e = 0; e < n.length; e++) {
			let r = n[e];
			r.nodeType === 8 && r.data.slice(0, 2) === "!$" ? r.remove() : t.push(r);
		}
		n = t;
	}
	for (; typeof n == "function";) n = n();
	if (t === n) return n;
	let o = typeof t, s = r !== void 0;
	if (e = s && n[0] && n[0].parentNode || e, o === "string" || o === "number") {
		if (a || o === "number" && (t = t.toString(), t === n)) return n;
		if (s) {
			let i = n[0];
			i && i.nodeType === 3 ? i.data !== t && (i.data = t) : i = document.createTextNode(t), n = Q(e, n, r, i);
		} else n = n !== "" && typeof n == "string" ? e.firstChild.data = t : e.textContent = t;
	} else if (t == null || o === "boolean") {
		if (a) return n;
		n = Q(e, n, r);
	} else if (o === "function") return v(() => {
		let i = t();
		for (; typeof i == "function";) i = i();
		n = Y(e, i, n, r);
	}), () => n;
	else if (Array.isArray(t)) {
		let o = [], c = n && Array.isArray(n);
		if (X(o, t, n, i)) return v(() => n = Y(e, o, n, r, !0)), () => n;
		if (a) {
			if (!o.length) return n;
			if (r === void 0) return n = [...e.childNodes];
			let t = o[0];
			if (t.parentNode !== e) return n;
			let i = [t];
			for (; (t = t.nextSibling) !== r;) i.push(t);
			return n = i;
		}
		if (o.length === 0) {
			if (n = Q(e, n, r), s) return n;
		} else c ? n.length === 0 ? Z(e, o, r) : ie(e, n, o) : (n && Q(e), Z(e, o));
		n = o;
	} else if (t.nodeType) {
		if (a && t.parentNode) return n = s ? [t] : t;
		if (Array.isArray(n)) {
			if (s) return n = Q(e, n, r, t);
			Q(e, n, null, t);
		} else n == null || n === "" || !e.firstChild ? e.appendChild(t) : e.replaceChild(t, e.firstChild);
		n = t;
	}
	return n;
}
function X(e, t, n, r) {
	let i = !1;
	for (let a = 0, o = t.length; a < o; a++) {
		let o = t[a], s = n && n[e.length], c;
		if (!(o == null || o === !0 || o === !1)) if ((c = typeof o) == "object" && o.nodeType) e.push(o);
		else if (Array.isArray(o)) i = X(e, o, s) || i;
		else if (c === "function") if (r) {
			for (; typeof o == "function";) o = o();
			i = X(e, Array.isArray(o) ? o : [o], Array.isArray(s) ? s : [s]) || i;
		} else e.push(o), i = !0;
		else {
			let t = String(o);
			s && s.nodeType === 3 && s.data === t ? e.push(s) : e.push(document.createTextNode(t));
		}
	}
	return i;
}
function Z(e, t, n = null) {
	for (let r = 0, i = t.length; r < i; r++) e.insertBefore(t[r], n);
}
function Q(e, t, n, r) {
	if (n === void 0) return e.textContent = "";
	let i = r || document.createTextNode("");
	if (t.length) {
		let r = !1;
		for (let a = t.length - 1; a >= 0; a--) {
			let o = t[a];
			if (i !== o) {
				let t = o.parentNode === e;
				!r && !a ? t ? e.replaceChild(i, o) : e.insertBefore(i, n) : t && o.remove();
			} else r = !0;
		}
	} else e.insertBefore(i, n);
	return [i];
}
//#endregion
//#region src/main.tsx
var oe = /*#__PURE__*/ G("<div class=alert id=sign-in-error role=alert aria-live=assertive>"), se = /*#__PURE__*/ G("<fieldset class=identity-list><legend>Select the user you want to act as"), ce = /*#__PURE__*/ G("<main class=login-shell><section class=card aria-labelledby=login-title><header class=card-header><div class=identity aria-label=Hoocloak><span class=identity-mark aria-hidden=true>H</span><span class=brand>Hoocloak</span></div><p class=eyebrow>Development identity</p><h1 id=login-title></h1><p class=client>Continue to <strong></strong></p></header><form method=post><input type=hidden name=authRequestID><input type=hidden name=csrf><button type=submit></button></form><p class=notice><span aria-hidden=true>Dev</span>For local development only."), le = /*#__PURE__*/ G("<div class=field><label for=username>Username</label><input id=username name=username autocomplete=username autofocus required>"), ue = /*#__PURE__*/ G("<div class=field><label for=password>Password</label><input id=password name=password type=password autocomplete=current-password required>"), de = /*#__PURE__*/ G("<label class=identity-option><input type=radio name=identity><span><strong></strong><small>@");
function fe(e) {
	let t = e.dataset.basePath ?? "";
	if (!/^\/realms\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(t)) throw Error("Invalid realm base path");
	let n = JSON.parse(e.dataset.identities ?? "[]");
	return {
		basePath: t,
		requestId: e.dataset.requestId ?? "",
		client: e.dataset.client ?? "",
		csrf: e.dataset.csrf ?? "",
		mode: e.dataset.mode === "select" ? "select" : "password",
		username: e.dataset.username ?? "",
		selectedId: e.dataset.selectedId ?? "",
		identities: n,
		error: e.dataset.error ?? ""
	};
}
function pe(e) {
	let t = () => e.error.trim().length > 0;
	return (() => {
		var n = ce(), r = n.firstChild, i = r.firstChild, a = i.firstChild.nextSibling.nextSibling, o = a.nextSibling.firstChild.nextSibling, s = i.nextSibling, c = s.firstChild, l = c.nextSibling, u = l.nextSibling;
		return q(a, () => e.mode === "select" ? "Choose an identity" : "Sign in"), q(o, () => e.client), q(r, L(W, {
			get when() {
				return t();
			},
			get children() {
				var t = oe();
				return q(t, () => e.error), t;
			}
		}), s), q(s, L(W, {
			get when() {
				return e.mode === "select";
			},
			get fallback() {
				return [(() => {
					var n = le(), r = n.firstChild.nextSibling;
					return v((e) => {
						var n = t() ? "true" : void 0, i = t() ? "sign-in-error" : void 0;
						return n !== e.e && K(r, "aria-invalid", e.e = n), i !== e.t && K(r, "aria-describedby", e.t = i), e;
					}, {
						e: void 0,
						t: void 0
					}), v(() => r.value = e.username), n;
				})(), (() => {
					var e = ue(), n = e.firstChild.nextSibling;
					return v((e) => {
						var r = t() ? "true" : void 0, i = t() ? "sign-in-error" : void 0;
						return r !== e.e && K(n, "aria-invalid", e.e = r), i !== e.t && K(n, "aria-describedby", e.t = i), e;
					}, {
						e: void 0,
						t: void 0
					}), e;
				})()];
			},
			get children() {
				var n = se();
				return n.firstChild, q(n, () => e.identities.map((t, n) => (() => {
					var r = de(), i = r.firstChild, a = i.nextSibling.firstChild, o = a.nextSibling;
					return o.firstChild, i.required = n === 0, i.autofocus = n === 0, q(a, () => t.Name || t.Username), q(o, () => t.Username, null), q(o, (() => {
						var e = re(() => !!t.Email);
						return () => e() ? ` · ${t.Email}` : "";
					})(), null), v(() => i.value = t.ID), v(() => i.checked = t.ID === e.selectedId), r;
				})()), null), v(() => K(n, "aria-describedby", t() ? "sign-in-error" : void 0)), n;
			}
		}), u), q(u, () => e.mode === "select" ? "Continue as selected user" : "Sign in"), v(() => K(s, "action", `${e.basePath}/login`)), v(() => c.value = e.requestId), v(() => l.value = e.csrf), n;
	})();
}
var $ = document.getElementById("login-root");
if (!($ instanceof HTMLDivElement)) throw Error("Login root was not found");
ae(() => L(pe, H(() => fe($))), $);
//#endregion
