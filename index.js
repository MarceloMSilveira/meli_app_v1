import 'dotenv/config';
import express from 'express';
//import session from 'express-session';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg'

const {Pool} = pg

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set('trust proxy', 1);

// app.use(
//   session({
//     secret: process.env.SESSION_SECRET || 'dev-secret',
//     resave: false,
//     saveUninitialized: false,
//     cookie: {
//       httpOnly: true,
//       sameSite: 'none',
//       secure: true
//     }
//   })
// );

// ============================================
// 👇 NOVO: função para limpar states expirados
// ============================================
async function cleanExpiredPkceStates() {
  await pool.query(
    "DELETE FROM oauth_pkce WHERE created_at < NOW() - INTERVAL '10 minutes'"
  );
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
  await pool.query(
    `
    INSERT INTO accounts (
      meli_user_id,
      nickname,
      email,
      country_id,
      site_id,
      access_token,
      refresh_token,
      token_type,
      scope,
      expires_at
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    ON CONFLICT (meli_user_id)
    DO UPDATE SET
      nickname = EXCLUDED.nickname,
      email = EXCLUDED.email,
      country_id = EXCLUDED.country_id,
      site_id = EXCLUDED.site_id,
      access_token = EXCLUDED.access_token,
      refresh_token = EXCLUDED.refresh_token,
      token_type = EXCLUDED.token_type,
      scope = EXCLUDED.scope,
      expires_at = EXCLUDED.expires_at,
      updated_at = NOW()
    `,
    [
      String(account.meli_user_id),
      account.nickname,
      account.email,
      account.country_id,
      account.site_id,
      account.access_token,
      account.refresh_token,
      account.token_type,
      account.scope,
      account.expires_at
    ]
  );
}

async function findAccountByMeliUserId(meliUserId) {
  const result = await pool.query(
    `
    SELECT *
    FROM accounts
    WHERE meli_user_id = $1
    `,
    [String(meliUserId)]
  );

  return result.rows[0];
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
  if (!account.refresh_token) {
    throw new Error('Conta sem refresh_token. Reconectar necessário.');
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

async function deleteAccountByMeliUserId(meliUserId) {
  await pool.query(
    `
    DELETE FROM accounts
    WHERE meli_user_id = $1
    `,
    [String(meliUserId)]
  );
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
  try {
    const result = await pool.query(`
      SELECT *
      FROM accounts
      ORDER BY created_at DESC
    `);

    res.render('home', { accounts: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).send(`Erro ao carregar contas: ${err.message}`);
  }
});

app.get('/auth/mercadolivre', async (req, res) => {
  
  // 👇 mostra página de instrução antes de iniciar o OAuth
  const skipInstructions = req.query.skip === '1';

  if (!skipInstructions) {
    return res.send(`
      <h2>Antes de conectar uma nova conta</h2>
      <p>Para conectar uma conta diferente do Mercado Livre, você precisa:</p>
      <ol>
        <li>Fazer logout do Mercado Livre no seu browser</li>
        <li>Ou usar uma aba anônima</li>
      </ol>
      <a href="/auth/mercadolivre?skip=1">Já fiz logout, continuar →</a>
      &nbsp;|&nbsp;
      <a href="https://www.mercadolivre.com.br/logout" target="_blank">Fazer logout do ML agora</a>
    `);
  }
  
  const state = crypto.randomUUID();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  try {
    await pool.query(
      'INSERT INTO oauth_pkce (state, code_verifier) VALUES ($1, $2)',
      [state, codeVerifier]
    );
  } catch (error) {
    console.error(`Erro ao tentar inserir codigo de verificação (pkce) no banco de dados: ${error.message}`)
    return res.status(500).send(`Erro ao tentar inserir codigo de verificação no banco de dados: ${error.message}`)
  }

  const authUrl = buildMeliAuthUrl(state, codeChallenge);
  console.log('Auth URL:', authUrl);
  res.redirect(authUrl)

});

app.get('/auth', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    // console.log('--- PKCE STEP 2 ---');
    // console.log('SESSION ID NO CALLBACK:', req.sessionID);
    // console.log('STATE recebido:', state);
    // console.log('STATE salvo na sessão:', req.session.meli_oauth_state);

    if (error) {
      return res.status(400).send(`Autorização recusada ou falhou: ${error}`);
    }

    if (!code) {
      return res.status(400).send('Código de autorização ausente.');
    }

    if (!state) {
      return res.status(400).send('State inválido.');
    }

    //const codeVerifier = req.session.meli_code_verifier;

    // 👇 NOVO: busca e já deleta o state do banco (evita reuso)
    // 👇 REMOVIDO: if (!state || state !== req.session.meli_oauth_state)
    let result = []
    try {
      result = await pool.query(
        'DELETE FROM oauth_pkce WHERE state = $1 RETURNING code_verifier',
        [state]
      );
    } catch (error) {
      console.error(`Erro ao tentar pegar estado e deletar do bd: ${error.message}`)
      return res.status(500).send(`Erro ao tentar pegar estado e deletar do bd: ${error.message}`)
    }

    //console.log('code_verifier da sessão:', codeVerifier);

     if (!result.rows.length) {
      return res.status(400).send('State inválido ou expirado.');
    }

    // 👇 NOVO: vem do banco agora
    // 👇 REMOVIDO: const codeVerifier = req.session.meli_code_verifier
    const codeVerifier = result.rows[0].code_verifier;

    if (!codeVerifier) {
      return res.status(400).send('Code verifier ausente na sessão.');
    }

    const tokenData = await exchangeCodeForToken(code, codeVerifier);

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

    res.render('success', { account });

  } catch (err) {
    console.error(err);
    res.status(500).send(`Erro no callback OAuth: ${err.message}`);
  }
});

app.get('/accounts/:meliUserId/test', async (req, res) => {
  try {
    const { meliUserId } = req.params;
    try {
      const accessToken = await getValidAccessTokenForUser(meliUserId);
    } catch (err) {
      if (err.message.includes('refresh_token')) {
        return res.send('Sua sessão expirou. Por favor, reconecte sua conta.');
      }
    }

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
  let accessToken = ''
  try {
    const { meliUserId } = req.params;

    try {
      accessToken = await getValidAccessTokenForUser(meliUserId);
    } catch (err) {
      if (err.message.includes('refresh_token')) {
        return res.send('Sua sessão expirou. Por favor, reconecte sua conta.');
      }
    }

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

//rota para desconectar:
app.post('/accounts/:meliUserId/disconnect', async (req, res) => {
  try {
    const { meliUserId } = req.params;

    await deleteAccountByMeliUserId(meliUserId);

    return res.redirect('/');
  } catch (err) {
    console.error(err);

    return res.status(500).send(`
      <h1>Erro ao desconectar conta</h1>
      <p>${err.message}</p>
      <p><a href="/">Voltar</a></p>
    `);
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta:${PORT}`);
});