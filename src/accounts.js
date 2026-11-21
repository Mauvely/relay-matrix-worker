// SPDX-License-Identifier: AGPL-3.0-or-later
const encoder = new TextEncoder();
const alphabet = /^[a-z0-9._=-]{1,128}$/;

export function secret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function digest(value) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))), (b) =>
    b.toString(16).padStart(2, '0')
  ).join('');
}

export function matrixError(status, errcode, error) {
  return { status, body: { errcode, error } };
}

// The operator assigns a unique endpoint to a canonical name before delegation.
// Reading both records over HTTPS binds that assignment to the domain owner's website.
export async function delegated(name, endpoint, read = fetch) {
  if (!/^[a-z0-9.-]+$/.test(name) || !/^[a-z0-9.-]+$/.test(endpoint)) return false;
  async function record(kind) {
    const response = await read('https://' + name + '/.well-known/matrix/' + kind, {
      redirect: 'manual',
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) throw Error(kind + ' discovery returned HTTP ' + response.status);
    return response.json();
  }
  const [client, server] = await Promise.all([record('client'), record('server')]);
  return (
    client?.['m.homeserver']?.base_url?.replace(/\/$/, '') === 'https://' + endpoint &&
    server?.['m.server'] === endpoint + ':443'
  );
}

export async function provision(storage, server, localpart, organisationId) {
  if (
    typeof localpart !== 'string' ||
    !alphabet.test(localpart) ||
    !(
      organisationId === null ||
      (typeof organisationId === 'string' && organisationId.length > 0 && organisationId.length <= 255)
    )
  )
    return matrixError(400, 'M_INVALID_PARAM', 'Invalid account or organisation');
  const key = 'account/' + localpart;
  const password = secret();
  const account = {
    userId: '@' + localpart + ':' + server,
    organisationId,
    passwordHash: await digest(password)
  };
  return storage.transaction(async (txn) => {
    if (await txn.get(key)) return matrixError(409, 'M_USER_IN_USE', 'Account already provisioned');
    await txn.put(key, account);
    return { status: 201, body: { user_id: account.userId, password } };
  });
}

export async function login(storage, server, body) {
  if (body?.type !== 'm.login.password')
    return matrixError(400, 'M_UNRECOGNIZED', 'Unsupported login method');
  const user = body.identifier?.type === 'm.id.user' ? body.identifier.user : body.user;
  if (typeof user !== 'string' || typeof body.password !== 'string' || body.password.length !== 64)
    return matrixError(403, 'M_FORBIDDEN', 'Invalid credentials');
  const local =
    user.startsWith('@') && user.endsWith(':' + server) ? user.slice(1, -server.length - 1) : user;
  const account = alphabet.test(local) && (await storage.get('account/' + local));
  if (!account || (await digest(body.password)) !== account.passwordHash)
    return matrixError(403, 'M_FORBIDDEN', 'Invalid credentials');
  return startSession(storage, account, body);
}

async function startSession(storage, account, body) {
  const deviceId = body.device_id ?? crypto.randomUUID();
  if (typeof deviceId !== 'string' || !deviceId || deviceId.length > 255)
    return matrixError(400, 'M_INVALID_PARAM', 'Invalid device ID');
  const token = secret();
  await storage.put('session/' + (await digest(token)), {
    user_id: account.userId,
    device_id: deviceId,
    organisationId: account.organisationId
  });
  return { status: 200, body: { user_id: account.userId, device_id: deviceId, access_token: token } };
}

export function ssoRedirect(address, clients) {
  try {
    const url = new URL(address);
    if (url.username || url.password || url.searchParams.has('loginToken')) return null;
    const loopback = url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname) && url.port;
    return (loopback || clients?.includes(url.origin + url.pathname)) ? url : null;
  } catch {
    return null;
  }
}

export async function issueLoginCode(storage, sql, accountId) {
  const userId = await storage.get('mauvely-id/' + accountId);
  if (!userId) throw Error('No bound account');
  const token = secret();
  const hash = await digest(token);
  sql.exec('DELETE FROM sso_codes WHERE expires <= ?', Date.now());
  sql.exec('INSERT INTO sso_codes VALUES(?,?,?)', hash, userId, Date.now() + 60000);
  return token;
}

export async function redeemLoginCode(storage, sql, server, body) {
  if (!/^[0-9a-f]{64}$/.test(body.token ?? '')) return matrixError(403, 'M_FORBIDDEN', 'Invalid login token');
  const hash = await digest(body.token);
  const rows = sql.exec('DELETE FROM sso_codes WHERE hash=? AND expires>? RETURNING user', hash, Date.now()).toArray();
  const id = rows[0]?.user;
  const account = id && id.endsWith(':' + server) && await storage.get('account/' + id.slice(1, -server.length - 1));
  if (!account?.accountId || account.userId !== id) return matrixError(403, 'M_FORBIDDEN', 'Invalid login token');
  return startSession(storage, account, body);
}

export async function session(storage, authorization, logout = false) {
  const token = /^Bearer ([0-9a-f]{64})$/i.exec(authorization ?? '')?.[1];
  if (!token) return matrixError(401, 'M_MISSING_TOKEN', 'A bearer token is required');
  const key = 'session/' + (await digest(token));
  const value = await storage.get(key);
  if (!value) return matrixError(401, 'M_UNKNOWN_TOKEN', 'Unknown access token');
  if (logout) await storage.delete(key);
  return { status: 200, body: logout ? {} : { user_id: value.user_id, device_id: value.device_id } };
}

// Called exclusively through the accounts service binding. No reusable password is created.
export async function ensureManagedAccount(storage, server, accountId, localpart, organisationId, profile) {
  if (typeof accountId !== 'string' || !accountId.startsWith('usr_') || accountId.length > 128 ||
      typeof localpart !== 'string' || !alphabet.test(localpart) ||
      !(organisationId === null || (typeof organisationId === 'string' && organisationId.length > 0)))
    throw Error('Invalid account identity');
  const userId = '@' + localpart + ':' + server;
  return storage.transaction(async (txn) => {
    const key = 'account/' + localpart;
    const ownerKey = 'mauvely-id/' + accountId;
    const prior = await txn.get(key);
    const existing = await txn.get(ownerKey);
    if ((prior && prior.accountId !== accountId) || (existing && existing !== userId))
      throw Error('Matrix identity already claimed');
    const account = {...prior,userId,accountId,organisationId};
    if (profile && (!prior?.profileRevision || profile.revision >= prior.profileRevision)) {
      if (!Number.isSafeInteger(profile.revision) || profile.revision < 1 || typeof profile.name !== 'string' ||
          profile.name.length > 120) throw Error('Invalid account profile');
      const prefix = 'avatars/' + accountId + '/';
      const id = typeof profile.avatarKey === 'string' && profile.avatarKey.startsWith(prefix)
        ? profile.avatarKey.slice(prefix.length) : null;
      if (profile.avatarKey !== null && (!id || !/^[a-f0-9-]{36}$/.test(id))) throw Error('Invalid account avatar');
      if (prior?.avatarId && id !== prior.avatarId) await txn.delete('avatar-source/'+prior.avatarId);
      if (id) await txn.put('avatar-source/'+id,profile.avatarKey);
      account.profileRevision = profile.revision;
      account.avatarId = id;
      account.profile = {displayname:profile.name || localpart,...(id ? {avatar_url:'mxc://'+server+'/avatar-'+id} : {})};
    }
    await txn.put(key, account);
    await txn.put(ownerKey, userId);
    return userId;
  });
}
