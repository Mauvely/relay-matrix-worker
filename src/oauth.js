// SPDX-License-Identifier: AGPL-3.0-or-later
import { secret, digest } from './accounts.js';
import { limited } from './media.js';

const prefix = '/_matrix/oauth/';
const deviceGrant = 'urn:ietf:params:oauth:grant-type:device_code';
const grants = ['authorization_code', 'refresh_token', deviceGrant];
const ttl = 600000;
const noStore = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'Access-Control-Allow-Origin': '*'
};
const alphabet = 'BCDFGHJKLMNPQRSTVWXYZ23456789';
const enc = new TextEncoder();
function error(code, status = 400) {
  throw Object.assign(Error(code), { oauth: code, status });
}
function reply(body, status = 200) {
  return { body, status };
}
export function oauthSchema(sql) {
  sql.exec(`CREATE TABLE IF NOT EXISTS oauth_clients(id TEXT PRIMARY KEY,redirects TEXT,label TEXT);
    CREATE TABLE IF NOT EXISTS oauth_requests(id TEXT PRIMARY KEY,params TEXT,code_hash TEXT UNIQUE,user_code TEXT UNIQUE,user TEXT,expires INTEGER,poll INTEGER DEFAULT 0);
    CREATE INDEX IF NOT EXISTS oauth_request_expiry ON oauth_requests(expires);
    CREATE TABLE IF NOT EXISTS oauth_sessions(access TEXT PRIMARY KEY,refresh TEXT UNIQUE,client TEXT,user TEXT,device TEXT,scope TEXT,expires INTEGER,renew INTEGER);`);
}
export function metadata(origin) {
  const url = origin + prefix;
  return {
    issuer: url + 'issuer',
    authorization_endpoint: url + 'authorize',
    token_endpoint: url + 'token',
    revocation_endpoint: url + 'revoke',
    registration_endpoint: url + 'register',
    device_authorization_endpoint: url + 'device',
    response_types_supported: ['code'],
    response_modes_supported: ['query', 'fragment'],
    grant_types_supported: grants,
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['urn:matrix:client:api:*'],
    token_endpoint_auth_methods_supported: ['none']
  };
}
function scopes(scope) {
  if (typeof scope !== 'string' || scope.length > 512) error('invalid_scope');
  const parts = scope.split(' '),
    ids = parts.filter((s) => s.startsWith('urn:matrix:client:device:'));
  const id = ids[0]?.slice('urn:matrix:client:device:'.length);
  if (
    parts.length !== 2 ||
    !parts.includes('urn:matrix:client:api:*') ||
    ids.length !== 1 ||
    !/^[A-Za-z0-9._~+=/-]{1,128}$/.test(id ?? '')
  )
    error('invalid_scope');
  return id;
}
async function pkce(verifier) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(verifier)));
  return btoa(String.fromCharCode(...bytes))
    .replace(/=+$/, '')
    .replaceAll('+', '-')
    .replaceAll('/', '_');
}
function registration(input, home) {
  if (
    !Array.isArray(input.redirect_uris) ||
    !input.redirect_uris.length ||
    input.redirect_uris.length > 8 ||
    (input.token_endpoint_auth_method && input.token_endpoint_auth_method !== 'none') ||
    input.grant_types?.some((g) => !grants.includes(g)) ||
    input.response_types?.some((g) => g !== 'code')
  )
    error('invalid_client_metadata');
  let label;
  const redirects = input.redirect_uris.map((raw) => {
    let url;
    try {
      url = new URL(raw);
    } catch {
      error('invalid_redirect_uri');
    }
    if (url.username || url.password || url.hash || url.search || raw !== url.href || raw.length > 1024)
      error('invalid_redirect_uri');
    const native = raw === 'io.element.android:/';
    const registered = home.env.SSO_CLIENTS?.includes(raw);
    let webClient = false;
    try {
      webClient = url.protocol === 'https:' && new URL(input.client_uri).origin === url.origin;
    } catch {
      /* optional metadata */
    }
    const loopback = url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname) && !!url.port;
    if (!native && !registered && !webClient && !loopback) error('invalid_redirect_uri');
    const name = native ? 'Element X for Android' : url.origin;
    if (label && label !== name) error('invalid_client_metadata');
    label = name;
    return raw;
  });
  return { redirects: [...new Set(redirects)].sort(), label };
}
function approval(origin, params, id, userCode) {
  const callback = new URL(prefix + 'approve', origin);
  callback.searchParams.set('request', id);
  callback.searchParams.set('application', params.label);
  if (userCode) callback.searchParams.set('user_code', userCode);
  return callback.href;
}
function toAccounts(server, target) {
  const url = new URL('/matrix-signin', 'https://' + server);
  url.searchParams.set('client', target);
  return { status: 302, location: url.href };
}
function makeUserCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  return [...bytes].map((n, i) => (i === 5 ? '-' : '') + alphabet[n % alphabet.length]).join('');
}
function client(sql, id) {
  if (typeof id !== 'string' || !id) error('invalid_client');
  const c = sql.exec('SELECT * FROM oauth_clients WHERE id=?', id).toArray()[0];
  if (!c) error('invalid_client');
  return c;
}
export async function approveOAuth(home, server, accountId, target) {
  const origin = 'https://' + home.env.ACCOUNT_ENDPOINT,
    url = new URL(target);
  if (url.origin !== origin || url.pathname !== prefix + 'approve') return null;
  const id = url.searchParams.get('request') ?? '';
  const user = await home.ctx.storage.get('mauvely-id/' + accountId);
  if (!user || !user.endsWith(':' + server)) error('access_denied');
  const code = secret(),
    hash = await digest(code);
  const r = home.sql
    .exec('SELECT * FROM oauth_requests WHERE id=? AND user IS NULL AND expires>?', id, Date.now())
    .toArray()[0];
  if (!r) error('invalid_request');
  const params = JSON.parse(r.params);
  if (approval(origin, params, id, r.user_code) !== target) error('invalid_request');
  if (home.sql.exec('SELECT 1 FROM devices WHERE user=? AND device=?', user, params.device).toArray().length)
    error('invalid_grant');
  if (r.user_code) {
    home.sql.exec('UPDATE oauth_requests SET user=? WHERE id=?', user, id);
    return origin + prefix + 'complete';
  }
  home.sql.exec('UPDATE oauth_requests SET user=?,code_hash=? WHERE id=?', user, hash, id);
  const callback = new URL(params.redirect);
  const values = new URLSearchParams({ code, state: params.state, iss: metadata(origin).issuer });
  if (params.mode === 'fragment') callback.hash = values.toString();
  else for (const [k, v] of values) callback.searchParams.set(k, v);
  return callback.href;
}
export async function oauthOperation(home, server, op, input) {
  const { sql } = home,
    origin = 'https://' + home.env.ACCOUNT_ENDPOINT;
  const now = Date.now();
  sql.exec('DELETE FROM oauth_requests WHERE expires<=?', now);
  if (op === 'register') {
    const { redirects, label } = registration(input, home);
    const id = await digest(JSON.stringify(redirects));
    if (
      !sql.exec('SELECT 1 FROM oauth_clients WHERE id=?', id).toArray().length &&
      sql.exec('SELECT COUNT(*) AS n FROM oauth_clients').one().n >= 8192
    )
      error('temporarily_unavailable', 503);
    sql.exec('INSERT OR IGNORE INTO oauth_clients VALUES(?,?,?)', id, JSON.stringify(redirects), label);
    return reply(
      {
        client_id: id,
        client_name: label,
        redirect_uris: redirects,
        grant_types: grants,
        response_types: ['code'],
        token_endpoint_auth_method: 'none'
      },
      201
    );
  }
  if (op === 'verify') {
    const uc = String(input.user_code ?? '')
      .trim()
      .toUpperCase();
    const r = sql.exec('SELECT * FROM oauth_requests WHERE user_code=? AND user IS NULL', uc).toArray()[0];
    if (!r) error('invalid_request');
    return toAccounts(server, approval(origin, JSON.parse(r.params), r.id, uc));
  }
  if (op === 'token') sql.exec('DELETE FROM oauth_sessions WHERE renew<=?', now);
  if (op === 'revoke') {
    const hash = await digest(input.token ?? '');
    sql.exec(
      'DELETE FROM oauth_sessions WHERE (access=? OR refresh=?) AND client=?',
      hash,
      hash,
      input.client_id ?? ''
    );
    return reply({});
  }
  const c = client(sql, input.client_id);
  if (op === 'authorize' || op === 'device') {
    const params = { client: c.id, label: c.label, scope: input.scope, device: scopes(input.scope) };
    let userCode = null,
      deviceCode = null,
      codeHash = null;
    if (op === 'authorize') {
      if (
        input.response_type !== 'code' ||
        !JSON.parse(c.redirects).includes(input.redirect_uri) ||
        input.code_challenge_method !== 'S256' ||
        !/^[a-zA-Z0-9_-]{43}$/.test(input.code_challenge ?? '') ||
        typeof input.state !== 'string' ||
        !input.state ||
        input.state.length > 1024 ||
        !['query', 'fragment'].includes(input.response_mode ?? 'query')
      )
        error('invalid_request');
      Object.assign(params, {
        challenge: input.code_challenge,
        redirect: input.redirect_uri,
        state: input.state,
        mode: input.response_mode ?? 'query'
      });
    } else {
      userCode = makeUserCode();
      deviceCode = secret();
      codeHash = await digest(deviceCode);
    }
    if (sql.exec('SELECT COUNT(*) AS n FROM oauth_requests').one().n >= 4096)
      error('temporarily_unavailable', 503);
    const id = crypto.randomUUID();
    sql.exec(
      'INSERT INTO oauth_requests(id,params,code_hash,user_code,expires) VALUES(?,?,?,?,?)',
      id,
      JSON.stringify(params),
      codeHash,
      userCode,
      now + ttl
    );
    if (!deviceCode) return toAccounts(server, approval(origin, params, id, null));
    const uri = origin + prefix + 'verify';
    return reply({
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: uri,
      verification_uri_complete: uri + '?user_code=' + userCode,
      expires_in: ttl / 1000,
      interval: 5
    });
  }
  if (op !== 'token' || !grants.includes(input.grant_type)) error('unsupported_grant_type');
  const access = secret(),
    refresh = secret();
  const [accessHash, refreshHash, presented, challenge] = await Promise.all([
    digest(access),
    digest(refresh),
    digest(input.refresh_token ?? input.device_code ?? input.code ?? ''),
    pkce(input.code_verifier ?? '')
  ]);
  return home.ctx.storage.transactionSync(() => {
    let user, device, scope;
    if (input.grant_type === 'refresh_token') {
      const r = sql
        .exec('SELECT * FROM oauth_sessions WHERE refresh=? AND client=? AND renew>?', presented, c.id, now)
        .toArray()[0];
      if (!r) error('invalid_grant');
      ({ user, device, scope } = r);
      sql.exec('DELETE FROM oauth_sessions WHERE refresh=?', presented);
    } else {
      const r = sql
        .exec('SELECT * FROM oauth_requests WHERE code_hash=? AND expires>?', presented, now)
        .toArray()[0];
      if (!r) error('invalid_grant');
      const p = JSON.parse(r.params);
      if (p.client !== c.id || !!r.user_code !== (input.grant_type === deviceGrant)) error('invalid_grant');
      if (r.user_code && !r.user) {
        if (r.poll > now - 4500) return reply({ error: 'slow_down' }, 400);
        sql.exec('UPDATE oauth_requests SET poll=? WHERE id=?', now, r.id);
        return reply({ error: 'authorization_pending' }, 400);
      }
      if (
        !r.user ||
        (!r.user_code &&
          (input.redirect_uri !== p.redirect ||
            !/^[A-Za-z0-9._~-]{43,128}$/.test(input.code_verifier ?? '') ||
            challenge !== p.challenge))
      )
        error('invalid_grant');
      user = r.user;
      device = p.device;
      scope = p.scope;
      if (sql.exec('SELECT 1 FROM devices WHERE user=? AND device=?', user, device).toArray().length)
        error('invalid_grant');
      sql.exec('INSERT INTO devices VALUES(?,?)', user, device);
      sql.exec('DELETE FROM oauth_requests WHERE id=?', r.id);
    }
    sql.exec(
      'INSERT INTO oauth_sessions VALUES(?,?,?,?,?,?,?,?)',
      accessHash,
      refreshHash,
      c.id,
      user,
      device,
      scope,
      now + 3600000,
      now + 90 * 86400000
    );
    return reply({
      token_type: 'Bearer',
      access_token: access,
      refresh_token: refresh,
      scope,
      expires_in: 3600
    });
  });
}
export async function oauthSession(home, authorization, logout) {
  const token = /^Bearer ([a-f0-9]{64})$/i.exec(authorization ?? '')?.[1];
  if (!token) return null;
  const hash = await digest(token);
  const r = home.sql
    .exec(
      'SELECT user,device FROM oauth_sessions WHERE access=? AND expires>? AND renew>?',
      hash,
      Date.now(),
      Date.now()
    )
    .toArray()[0];
  if (!r) return null;
  if (logout) home.sql.exec('DELETE FROM oauth_sessions WHERE access=?', hash);
  return reply(logout ? {} : { user_id: r.user, device_id: r.device });
}
export async function oauthRoute(request, home, server) {
  const url = new URL(request.url);
  if (
    url.pathname === '/_matrix/client/v1/auth_metadata' ||
    url.pathname === '/_matrix/client/unstable/org.matrix.msc2965/auth_metadata'
  )
    return Response.json(metadata(url.origin), { headers: noStore });
  if (!url.pathname.startsWith(prefix)) return null;
  const op = url.pathname.slice(prefix.length);
  const page = (body) =>
    new Response(
      '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Mauvely sign-in</title><main>' +
        body +
        '</main></html>',
      {
        headers: {
          ...noStore,
          'content-type': 'text/html; charset=utf-8',
          'content-security-policy':
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        }
      }
    );
  if (op === 'complete' && request.method === 'GET')
    return page('<h1>Device approved</h1><p>Return to Element to finish signing in.</p>');
  if (op === 'verify' && request.method === 'GET' && !url.searchParams.has('user_code'))
    return page(
      '<h1>Link a Matrix device</h1><form><label>Code shown on your new device <input required name="user_code" autocomplete="off"></label> <button>Continue</button></form>'
    );
  const get = ['authorize', 'verify'].includes(op),
    post = ['register', 'device', 'token', 'revoke'].includes(op);
  if (!((get && request.method === 'GET') || (post && request.method === 'POST')))
    return Response.json({ error: 'invalid_request' }, { status: 404, headers: noStore });
  let input;
  try {
    if (get) input = Object.fromEntries(url.searchParams);
    else {
      const raw = new TextDecoder().decode(await limited(request.body, 16384));
      input = op === 'register' ? JSON.parse(raw) : Object.fromEntries(new URLSearchParams(raw));
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw Error();
  } catch {
    return Response.json({ error: 'invalid_request' }, { status: 400, headers: noStore });
  }
  const result = await home.oauth(server, op, input);
  return result.location
    ? new Response(null, { status: 302, headers: { ...noStore, location: result.location } })
    : Response.json(result.body, { status: result.status, headers: noStore });
}
