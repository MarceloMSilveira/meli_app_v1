import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_FILE = path.join(__dirname, 'db.json');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax'
    }
  })
);

async function ensureDb() {
  try {
    await fs.access(DB_FILE);
  } catch {
    await fs.writeFile(DB_FILE, JSON.stringify({ accounts: [] }, null, 2));
  }
}

async function readDb() {
  await ensureDb();
  const raw = await fs.readFile(DB_FILE, 'utf-8');
  return JSON.parse(raw);
}

async function writeDb(data) {
  await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2));
}

function base64UrlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(32));
}

function generateCodeChallenge(codeVerifier) {
  return base64UrlEncode(
    crypto.createHash('sha256').update(codeVerifier).digest()
  );
}

function buildMeliAuthUrl(state, codeChallenge) {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.ML_CLIENT_ID,
    redirect_uri: process.env.ML_REDIRECT_URI,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  return `https://auth.mercadolivre.com.br/authorization?${params.toString()}`;
}

async function exchangeCodeForToken(code, codeVerifier) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: process.env.ML_CLIENT_ID,
    client_secret: process.env.ML_CLIENT_SECRET,
    code,
    redirect_uri: process.env.ML_REDIRECT_URI,
    code_verifier: codeVerifier
  });
  console.log('--- PKCE STEP 3 ---');
  console.log('Sending code_verifier:', codeVerifier);
  const response = await fetch('https://api.mercadolibre.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json'
    },
    body
  });

  const text = await response.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Resposta não-JSON na troca de token: ${text}`);
  }

  if (!response.ok) {
    throw new Error(`Erro ao trocar code por token: ${JSON.stringify(data)}`);
  }

  return data;
}

async function refreshAccessToken(refreshToken) {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: process.env.ML_CLIENT_ID,
    client_secret: process.env.ML_CLIENT_SECRET,
    refresh_token: refreshToken
  });

  const response = await fetch('https://api.mercadolibre.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json'
    },
    body
  });

  const text = await response.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Resposta não-JSON no refresh: ${text}`);
  }

  if (!response.ok) {
    throw new Error(`Erro ao renovar token: ${JSON.stringify(data)}`);
  }

  return data;
}

async function getMeliUserMe(accessToken) {
  const response = await fetch('https://api.mercadolibre.com/users/me', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json'
    }
  });

  const text = await response.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Resposta não-JSON em /users/me: ${text}`);
  }

  if (!response.ok) {
    throw new Error(`Erro ao consultar /users/me: ${JSON.stringify(data)}`);
  }

  return data;
}

function computeExpiresAt(expiresInSeconds) {
  return new Date(Date.now() + expiresInSeconds * 1000).toISOString();
}

async function saveOrUpdateAccount(account) {
  const db = await readDb();
  const index = db.accounts.findIndex(a => a.meli_user_id === account.meli_user_id);

  if (index >= 0) {
    db.accounts[index] = {
      ...db.accounts[index],
      ...account,
      updated_at: new Date().toISOString()
    };
  } else {
    db.accounts.push({
      ...account,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });
  }

  await writeDb(db);
}

async function findAccountByMeliUserId(meliUserId) {
  const db = await readDb();
  return db.accounts.find(a => String(a.meli_user_id) === String(meliUserId));
}

async function getValidAccessTokenForUser(meliUserId) {
  const account = await findAccountByMeliUserId(meliUserId);

  if (!account) {
    throw new Error('Conta não encontrada.');
  }

  const expiresAtMs = new Date(account.expires_at).getTime();
  const now = Date.now();
  const marginMs = 60 * 1000;

  if (expiresAtMs > now + marginMs) {
    return account.access_token;
  }

  const refreshed = await refreshAccessToken(account.refresh_token);

  const updatedAccount = {
    ...account,
    access_token: refreshed.access_token,
    refresh_token: refreshed.refresh_token,
    token_type: refreshed.token_type,
    scope: refreshed.scope,
    expires_at: computeExpiresAt(refreshed.expires_in)
  };

  await saveOrUpdateAccount(updatedAccount);

  return updatedAccount.access_token;
}

//funcões adicionais para conexão com apps script

async function mlApiFetch(path, accessToken) {
  const response = await fetch(`https://api.mercadolibre.com${path}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json'
    }
  });

  const text = await response.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Resposta não-JSON do Mercado Livre: ${text}`);
  }

  if (!response.ok) {
    throw new Error(`Erro Mercado Livre: ${JSON.stringify(data)}`);
  }

  return data;
}

async function getSellerItemIds(accessToken, userId) {
  const data = await mlApiFetch(`/users/${userId}/items/search`, accessToken);
  return data.results || [];
}

async function getItemDetails(accessToken, itemId) {
  const item = await mlApiFetch(`/items/${itemId}`, accessToken);

  return {
    item_id: item.id,
    title: item.title,
    price: item.price
  };
}

async function buildProductsPayload(accessToken, userId) {
  const itemIds = await getSellerItemIds(accessToken, userId);

  if (!itemIds.length) {
    return [];
  }

  const items = await Promise.all(itemIds.map(itemId => getItemDetails(accessToken, itemId)));
  return items;
}

async function sendProductsToAppsScript(products) {
  const response = await fetch(process.env.APPS_SCRIPT_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(products)
  });

  const text = await response.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Resposta inválida do Apps Script: ${text}`);
  }

  if (!response.ok) {
    throw new Error(`Erro ao enviar para Apps Script: ${JSON.stringify(data)}`);
  }

  return data;
}


app.get('/', async (req, res) => {
  const db = await readDb();
  res.render('home', { accounts: db.accounts });
});

app.get('/auth/mercadolivre', (req, res) => {
  const state = crypto.randomUUID();

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  console.log('--- PKCE STEP 1 ---');
  console.log('code_verifier:', codeVerifier);
  console.log('code_challenge:', codeChallenge);

  req.session.meli_oauth_state = state;
  req.session.meli_code_verifier = codeVerifier;

  const authUrl = buildMeliAuthUrl(state, codeChallenge);
  console.log('Auth URL:', authUrl);
  res.redirect(authUrl);
});

app.get('/auth', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send(`Autorização recusada ou falhou: ${error}`);
    }

    if (!code) {
      return res.status(400).send('Código de autorização ausente.');
    }

    if (!state || state !== req.session.meli_oauth_state) {
      return res.status(400).send('State inválido.');
    }
    console.log('--- PKCE STEP 2 ---');
    console.log('Session code_verifier:', req.session.meli_code_verifier);
    const codeVerifier = req.session.meli_code_verifier;

    if (!codeVerifier) {
      return res.status(400).send('Code verifier ausente na sessão.');
    }

    let tokenData;

    try {
      tokenData = await exchangeCodeForToken(code, codeVerifier);
    } finally {
      delete req.session.meli_oauth_state;
      delete req.session.meli_code_verifier;
    }

    const userData = await getMeliUserMe(tokenData.access_token);

    const account = {
      meli_user_id: tokenData.user_id,
      nickname: userData.nickname,
      email: userData.email || null,
      country_id: userData.country_id || null,
      site_id: userData.site_id || null,
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      token_type: tokenData.token_type,
      scope: tokenData.scope,
      expires_at: computeExpiresAt(tokenData.expires_in)
    };

    await saveOrUpdateAccount(account);

    res.render('success', {
      account
    });
  } catch (err) {
    console.error(err);
    res.status(500).send(`Erro no callback OAuth: ${err.message}`);
  }
});

app.get('/accounts/:meliUserId/test', async (req, res) => {
  try {
    const { meliUserId } = req.params;
    const accessToken = await getValidAccessTokenForUser(meliUserId);

    const response = await fetch('https://api.mercadolibre.com/users/me', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json'
      }
    });

    const text = await response.text();

    res.status(response.status).type('application/json').send(text);
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

//rota para sincronizar com google sheets
//retornando json:
// app.post('/accounts/:meliUserId/sync-google-sheet', async (req, res) => {
//   try {
//     const { meliUserId } = req.params;

//     const accessToken = await getValidAccessTokenForUser(meliUserId);

//     const products = await buildProductsPayload(accessToken, meliUserId);

//     if (!products.length) {
//       return res.status(200).json({
//         ok: true,
//         message: 'Nenhum produto encontrado para enviar.',
//         quantity: 0
//       });
//     }

//     const appsScriptResult = await sendProductsToAppsScript(products);

//     return res.status(200).json({
//       ok: true,
//       message: 'Produtos enviados para o Google Sheets com sucesso.',
//       quantity: products.length,
//       appsScriptResult
//     });
//   } catch (err) {
//     console.error(err);
//     return res.status(500).json({
//       ok: false,
//       message: err.message
//     });
//   }
// });

//retornando html:
app.post('/accounts/:meliUserId/sync-google-sheet', async (req, res) => {
  try {
    const { meliUserId } = req.params;

    const accessToken = await getValidAccessTokenForUser(meliUserId);
    const products = await buildProductsPayload(accessToken, meliUserId);

    if (!products.length) {
      return res.send(`
        <h1>Sincronização concluída</h1>
        <p>Nenhum produto encontrado para enviar.</p>
        <p><a href="/">Voltar</a></p>
      `);
    }

    const appsScriptResult = await sendProductsToAppsScript(products);

    return res.send(`
      <h1>Sincronização concluída</h1>
      <p><strong>Quantidade enviada:</strong> ${products.length}</p>
      <pre>${JSON.stringify(appsScriptResult, null, 2)}</pre>
      <p><a href="/">Voltar</a></p>
    `);
  } catch (err) {
    console.error(err);
    return res.status(500).send(`
      <h1>Erro na sincronização</h1>
      <p>${err.message}</p>
      <p><a href="/">Voltar</a></p>
    `);
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});