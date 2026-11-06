require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { OAuth2Client } = require("google-auth-library");
const { GoogleGenAI } = require("@google/genai");

const app = express();
const PORT = process.env.PORT || 3000;
app.set("trust proxy", 1);

// Account utente locali: il file resta fuori da /public e contiene solo hash password.
const DATA_DIR = path.join(__dirname, "data");
const ACCOUNT_FILE = path.join(DATA_DIR, "users.json");
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(ACCOUNT_FILE)) fs.writeFileSync(ACCOUNT_FILE, "[]", { mode: 0o600 });
let utenti = JSON.parse(fs.readFileSync(ACCOUNT_FILE, "utf8"));
if (!Array.isArray(utenti)) throw new Error("Archivio utenti non valido.");

const SESSION_COOKIE = "nexcrank_session";
const DURATA_SESSIONE_MS = 30 * 24 * 60 * 60 * 1000;
const sessioni = new Map();
const tentativiAuth = new Map();
const salePasswordFittizio = crypto.randomBytes(16);
const clientGoogleAuth = new OAuth2Client();

function salvaUtenti() {
  const temporaneo = `${ACCOUNT_FILE}.tmp`;
  fs.writeFileSync(temporaneo, JSON.stringify(utenti, null, 2), { mode: 0o600 });
  fs.renameSync(temporaneo, ACCOUNT_FILE);
}

function limitaTentativiAuth(req, res, next) {
  const ora = Date.now();
  const ip = req.ip || req.socket.remoteAddress || "sconosciuto";
  let tentativo = tentativiAuth.get(ip);
  if (!tentativo || ora - tentativo.inizio >= 15 * 60 * 1000) tentativo = { inizio: ora, conteggio: 0 };
  tentativo.conteggio++;
  tentativiAuth.set(ip, tentativo);
  if (tentativiAuth.size > 10000) {
    for (const [chiave, valore] of tentativiAuth) {
      if (ora - valore.inizio >= 15 * 60 * 1000) tentativiAuth.delete(chiave);
    }
  }
  if (tentativo.conteggio > 8) {
    res.setHeader("Retry-After", "900");
    return res.status(429).json({ errore: "Troppi tentativi. Riprova tra 15 minuti." });
  }
  next();
}

function cookieDaRichiesta(req, nome) {
  const prefisso = `${nome}=`;
  for (const coppia of String(req.headers.cookie || "").split(";")) {
    const voce = coppia.trim();
    if (voce.startsWith(prefisso)) return decodeURIComponent(voce.slice(prefisso.length));
  }
  return "";
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function impostaCookieSessione(req, res, token, maxAge) {
  const secure = req.secure ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`);
}

function creaSessione(req, res, utente) {
  const token = crypto.randomBytes(32).toString("base64url");
  const scadenza = Date.now() + DURATA_SESSIONE_MS;
  sessioni.set(hashToken(token), { utenteId: utente.id, scadenza });
  impostaCookieSessione(req, res, token, Math.floor(DURATA_SESSIONE_MS / 1000));
}

function utenteDaSessione(req) {
  const token = cookieDaRichiesta(req, SESSION_COOKIE);
  if (!token) return null;
  const chiave = hashToken(token);
  const sessione = sessioni.get(chiave);
  if (!sessione || sessione.scadenza <= Date.now()) {
    sessioni.delete(chiave);
    return null;
  }
  return utenti.find(u => u.id === sessione.utenteId) || null;
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

function rispostaUtente(utente) {
  return { id: utente.id, email: utente.email, creatoIl: utente.creatoIl };
}

function creaTrasportoEmail() {
  const user = String(process.env.SMTP_USER || "").trim();
  const pass = String(process.env.SMTP_PASS || "").replace(/\s/g, "");
  if (!user || !pass) return null;
  const port = Number(process.env.SMTP_PORT || 465);
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port,
    secure: String(process.env.SMTP_SECURE || "true").toLowerCase() === "true",
    auth: { user, pass }
  });
}

function urlBaseApp() {
  const base = String(process.env.APP_BASE_URL || "").trim().replace(/\/+$/, "");
  if (!base) return null;
  try {
    const parsed = new URL(base);
    if (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

app.use(express.json({ limit: "18mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/auth/register", limitaTentativiAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ errore: "Inserisci un indirizzo email valido." });
  }
  if (password.length < 10 || password.length > 128) {
    return res.status(400).json({ errore: "La password deve contenere da 10 a 128 caratteri." });
  }
  if (utenti.some(u => u.email === email)) {
    return res.status(409).json({ errore: "Esiste già un account con questa email. Prova ad accedere." });
  }
  const salt = crypto.randomBytes(16);
  const utente = {
    id: crypto.randomUUID(),
    email,
    sale: salt.toString("hex"),
    hash: hashPassword(password, salt).toString("hex"),
    creatoIl: new Date().toISOString()
  };
  utenti.push(utente);
  try {
    salvaUtenti();
  } catch (errore) {
    utenti = utenti.filter(u => u.id !== utente.id);
    console.error("Nexcrank: impossibile salvare il nuovo account.", errore.message);
    return res.status(500).json({ errore: "Non sono riuscito a creare l'account. Riprova." });
  }
  creaSessione(req, res, utente);
  return res.status(201).json({ utente: rispostaUtente(utente) });
});

app.post("/api/auth/login", limitaTentativiAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!email || password.length > 128) return res.status(400).json({ errore: "Controlla email e password." });
  const utente = utenti.find(u => u.email === email);
  const sale = utente ? Buffer.from(utente.sale, "hex") : salePasswordFittizio;
  const hashInserito = hashPassword(password, sale);
  const hashSalvato = utente ? Buffer.from(utente.hash, "hex") : Buffer.alloc(64);
  const corretto = hashSalvato.length === hashInserito.length && crypto.timingSafeEqual(hashInserito, hashSalvato);
  if (!utente || !corretto) return res.status(401).json({ errore: "Email o password non corretti." });
  creaSessione(req, res, utente);
  return res.json({ utente: rispostaUtente(utente) });
});

app.get("/api/auth/google-config", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.json({ clientId: String(process.env.GOOGLE_CLIENT_ID || "").trim() });
});

app.post("/api/auth/google", limitaTentativiAuth, async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const clientId = String(process.env.GOOGLE_CLIENT_ID || "").trim();
  const credential = String(req.body.credential || "");
  if (!clientId) return res.status(503).json({ errore: "Accesso Google non configurato: aggiungi GOOGLE_CLIENT_ID nel file .env." });
  if (!credential || credential.length > 20000) return res.status(400).json({ errore: "Credenziale Google mancante o non valida." });

  let payload;
  try {
    const ticket = await clientGoogleAuth.verifyIdToken({ idToken: credential, audience: clientId });
    payload = ticket.getPayload();
  } catch (errore) {
    console.warn("Nexcrank: verifica token Google non riuscita.", errore.message);
    return res.status(401).json({ errore: "Non riesco a verificare l’accesso Google. Riprova." });
  }

  const googleSub = String(payload?.sub || "");
  const email = String(payload?.email || "").trim().toLowerCase();
  if (!googleSub || !email || payload.email_verified !== true) {
    return res.status(401).json({ errore: "Google non ha confermato l’indirizzo email. Usa l’accesso con email e password." });
  }

  let utente = utenti.find(u => u.googleSub === googleSub);
  if (!utente) {
    const accountEmail = utenti.find(u => u.email === email);
    if (accountEmail) {
      const password = String(req.body.password || "");
      if (!password) {
        return res.status(409).json({ collegaAccount: true, errore: "Esiste già un account Nexcrank con questa email. Inserisci la password Nexcrank per collegarlo a Google." });
      }
      if (!accountEmail.sale || !accountEmail.hash || password.length > 128) {
        return res.status(401).json({ errore: "Password Nexcrank non corretta." });
      }
      const hashInserito = hashPassword(password, Buffer.from(accountEmail.sale, "hex"));
      const hashSalvato = Buffer.from(accountEmail.hash, "hex");
      const corretto = hashSalvato.length === hashInserito.length && crypto.timingSafeEqual(hashInserito, hashSalvato);
      if (!corretto) return res.status(401).json({ errore: "Password Nexcrank non corretta." });

      accountEmail.googleSub = googleSub;
      try {
        salvaUtenti();
      } catch (errore) {
        delete accountEmail.googleSub;
        console.error("Nexcrank: impossibile collegare l’account Google.", errore.message);
        return res.status(500).json({ errore: "Non riesco a collegare l’account Google. Riprova." });
      }
      utente = accountEmail;
    } else {
      const sale = crypto.randomBytes(16);
      const passwordCasuale = crypto.randomBytes(48).toString("base64url");
      utente = {
        id: crypto.randomUUID(),
        email,
        sale: sale.toString("hex"),
        hash: hashPassword(passwordCasuale, sale).toString("hex"),
        googleSub,
        creatoIl: new Date().toISOString()
      };
      utenti.push(utente);
      try {
        salvaUtenti();
      } catch (errore) {
        utenti = utenti.filter(u => u.id !== utente.id);
        console.error("Nexcrank: impossibile salvare il nuovo account Google.", errore.message);
        return res.status(500).json({ errore: "Non riesco a creare l’account Google. Riprova." });
      }
    }
  }

  creaSessione(req, res, utente);
  return res.json({ utente: rispostaUtente(utente) });
});

app.get("/api/auth/me", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const utente = utenteDaSessione(req);
  if (!utente) return res.status(401).json({ utente: null });
  return res.json({ utente: rispostaUtente(utente) });
});

app.post("/api/auth/logout", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const token = cookieDaRichiesta(req, SESSION_COOKIE);
  if (token) sessioni.delete(hashToken(token));
  impostaCookieSessione(req, res, "", 0);
  return res.json({ ok: true });
});

app.post("/api/auth/forgot-password", limitaTentativiAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const trasporto = creaTrasportoEmail();
  const baseApp = urlBaseApp();
  if (!trasporto || !baseApp) {
    return res.status(503).json({ errore: "Recupero password non configurato: controlla le impostazioni email nel file .env." });
  }

  const email = String(req.body.email || "").trim().toLowerCase();
  const rispostaGenerica = { messaggio: "Se l’indirizzo appartiene a un account, riceverai un link per reimpostare la password." };
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.json(rispostaGenerica);

  const utente = utenti.find(u => u.email === email);
  if (!utente) return res.json(rispostaGenerica);

  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = hashToken(token);
  const scadenza = Date.now() + 30 * 60 * 1000;
  utente.tokenRecuperoHash = tokenHash;
  utente.tokenRecuperoScadenza = scadenza;
  try {
    salvaUtenti();
  } catch (errore) {
    delete utente.tokenRecuperoHash;
    delete utente.tokenRecuperoScadenza;
    console.error("Nexcrank: impossibile salvare il token di recupero.", errore.message);
    return res.status(500).json({ errore: "Non riesco a preparare il recupero. Riprova." });
  }

  const link = `${baseApp}/reset-password.html?token=${encodeURIComponent(token)}`;
  const mittente = String(process.env.SMTP_FROM || process.env.SMTP_USER).trim();
  trasporto.sendMail({
    from: mittente,
    to: utente.email,
    subject: "Reimposta la password di Nexcrank",
    text: `Hai richiesto di reimpostare la password Nexcrank. Apri questo link entro 30 minuti:\n\n${link}\n\nSe non hai richiesto tu il recupero, ignora questa email.`,
    html: `<p>Hai richiesto di reimpostare la password Nexcrank.</p><p><a href="${link}">Scegli una nuova password</a></p><p>Il link scade tra 30 minuti ed è utilizzabile una sola volta.</p><p>Se non hai richiesto tu il recupero, ignora questa email.</p>`
  }).catch(errore => {
    if (utente.tokenRecuperoHash === tokenHash) {
      delete utente.tokenRecuperoHash;
      delete utente.tokenRecuperoScadenza;
      try { salvaUtenti(); } catch (erroreSalvataggio) {
        console.error("Nexcrank: impossibile annullare un token non inviato.", erroreSalvataggio.message);
      }
    }
    console.error("Nexcrank: invio email recupero non riuscito.", errore.message);
  });

  return res.json(rispostaGenerica);
});

app.post("/api/auth/reset-password", limitaTentativiAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const token = String(req.body.token || "");
  const password = String(req.body.password || "");
  if (!token || token.length > 128) return res.status(400).json({ errore: "Il link non è valido o è scaduto. Richiedine uno nuovo." });
  if (password.length < 10 || password.length > 128) {
    return res.status(400).json({ errore: "La password deve contenere da 10 a 128 caratteri." });
  }

  const tokenHash = hashToken(token);
  const utente = utenti.find(u => u.tokenRecuperoHash === tokenHash && Number(u.tokenRecuperoScadenza) > Date.now());
  if (!utente) return res.status(400).json({ errore: "Il link non è valido o è scaduto. Richiedine uno nuovo." });

  const salt = crypto.randomBytes(16);
  const vecchioSale = utente.sale;
  const vecchioHash = utente.hash;
  delete utente.tokenRecuperoHash;
  delete utente.tokenRecuperoScadenza;
  utente.sale = salt.toString("hex");
  utente.hash = hashPassword(password, salt).toString("hex");
  try {
    salvaUtenti();
  } catch (errore) {
    utente.sale = vecchioSale;
    utente.hash = vecchioHash;
    console.error("Nexcrank: impossibile salvare la nuova password.", errore.message);
    return res.status(500).json({ errore: "Non riesco a salvare la nuova password. Riprova." });
  }

  for (const [chiave, sessione] of sessioni) {
    if (sessione.utenteId === utente.id) sessioni.delete(chiave);
  }
  return res.json({ ok: true });
});

// Limite essenziale per IP, senza dipendenze aggiuntive.
// In distribuzioni con più processi va sostituito con uno store condiviso.
const FINESTRA_RATE_LIMIT_MS = 15 * 60 * 1000;
const MASSIMO_RICHIESTE_PER_FINESTRA = 20;
const richiestePerIp = new Map();

function limitaRichiesteDiagnosi(req, res, next) {
  const ora = Date.now();
  const ip = req.ip || req.socket.remoteAddress || "sconosciuto";
  let record = richiestePerIp.get(ip);

  if (!record || ora - record.inizio >= FINESTRA_RATE_LIMIT_MS) {
    record = { inizio: ora, conteggio: 0 };
  }

  record.conteggio += 1;
  richiestePerIp.set(ip, record);

  if (richiestePerIp.size > 10000) {
    for (const [chiave, valore] of richiestePerIp) {
      if (ora - valore.inizio >= FINESTRA_RATE_LIMIT_MS) richiestePerIp.delete(chiave);
    }
  }

  res.setHeader("RateLimit-Limit", String(MASSIMO_RICHIESTE_PER_FINESTRA));
  res.setHeader("RateLimit-Remaining", String(Math.max(0, MASSIMO_RICHIESTE_PER_FINESTRA - record.conteggio)));

  if (record.conteggio > MASSIMO_RICHIESTE_PER_FINESTRA) {
    const retryDopo = Math.ceil((record.inizio + FINESTRA_RATE_LIMIT_MS - ora) / 1000);
    res.setHeader("Retry-After", String(Math.max(1, retryDopo)));
    return res.status(429).json({ errore: "Hai inviato troppe richieste. Riprova tra qualche minuto." });
  }

  next();
}

const ai = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY })
  : null;

// ---------------------------------------------------------------------------
// CONFIGURAZIONE RETRY / FALLBACK
// ---------------------------------------------------------------------------
// Nota: i modelli gemini-1.5-* e gemini-2.0-* sono stati dismessi (404 Not Found).
const MODELLO_PRINCIPALE =
  process.env.GEMINI_MODEL_PRIMARY || "gemini-3.5-flash-lite";
const MODELLO_FALLBACK =
  process.env.GEMINI_MODEL_FALLBACK || "gemini-3.8-flash";

// Un limite più ampio lascia spazio a guide complete; thinking basso riduce
// il rischio che il ragionamento consumi quasi tutto il limite di output.
function configGenerazione() {
  return {
    systemInstruction: ISTRUZIONI,
    maxOutputTokens: 8192,
    thinkingConfig: { thinkingLevel: "low" }
  };
}

const MAX_TENTATIVI = 3;        // tentativi per ciascun modello
const ATTESA_BASE_MS = 1000;    // 1s, 2s, 4s... (+ jitter)

const MESSAGGIO_DI_SICUREZZA =
  "⚠️ In questo momento non sono riuscito a completare la risposta. " +
  "Il tuo messaggio resta visibile nella chat: attendi qualche istante e riprova.";

const MESSAGGIO_INTERRUZIONE =
  "\n\n⚠️ La risposta si è interrotta a causa di un problema temporaneo " +
  "del servizio. Puoi chiedermi di continuare o riinviare il messaggio.";

const attendi = ms => new Promise(resolve => setTimeout(resolve, ms));

// Errori temporanei: vale la pena riprovare (503 / 429)
function erroreRiprovabile(errore) {
  const stato = Number(errore?.status ?? errore?.code ?? errore?.error?.code);
  if (stato === 503 || stato === 429) return true;

  const testo = String(errore?.message || "").toLowerCase();
  return (
    testo.includes("503") ||
    testo.includes("429") ||
    testo.includes("unavailable") ||
    testo.includes("resource_exhausted") ||
    testo.includes("overloaded") ||
    testo.includes("high demand")
  );
}

/**
 * Prova a generare la risposta con un singolo modello, con exponential backoff.
 * I tentativi si ripetono solo se non è ancora stato inviato nulla al client:
 * una volta iniziato lo streaming non si può ricominciare senza duplicare il testo.
 *
 * Ritorna { ok: true } oppure { ok: false, errore, haScritto, limiteToken }.
 */
async function generaConModello(modello, messaggi, res, abortSignal) {
  let haScritto = false;
  let ultimoErrore = null;
  let limiteToken = false;

  for (let tentativo = 1; tentativo <= MAX_TENTATIVI; tentativo++) {
    if (res.destroyed || res.writableEnded) {
      return { ok: false, haScritto, annullata: true };
    }
    try {
      const stream = await ai.models.generateContentStream({
        model: modello,
        contents: messaggi,
        config: { ...configGenerazione(), abortSignal }
      });

      for await (const chunk of stream) {
        // Uscire dal for-await chiude l'iteratore quando il client interrompe la richiesta.
        if (res.destroyed || res.writableEnded) {
          return { ok: false, haScritto, annullata: true };
        }
        if (chunk.candidates?.[0]?.finishReason === "MAX_TOKENS") {
          limiteToken = true;
        }
        if (chunk.text) {
          haScritto = true;
          res.write(chunk.text);
        }
      }

      return { ok: true, limiteToken };
    } catch (errore) {
      if (res.destroyed || res.writableEnded) {
        return { ok: false, haScritto, annullata: true };
      }
      ultimoErrore = errore;
      console.error(
        `Nexcrank: errore su ${modello} (tentativo ${tentativo}/${MAX_TENTATIVI}):`,
        errore.message
      );

      // Testo già inviato al client: impossibile riprovare in modo pulito.
      if (haScritto) {
        return { ok: false, errore, haScritto: true };
      }

      // Errore non temporaneo (es. 400, 401, 404): inutile riprovare
      // con lo stesso modello, si passa subito al successivo.
      if (!erroreRiprovabile(errore)) {
        if (Number(errore?.status) === 404) {
          console.error(
            `Nexcrank: il modello "${modello}" non esiste o è stato dismesso. ` +
            "Aggiorna GEMINI_MODEL_PRIMARY / GEMINI_MODEL_FALLBACK."
          );
        }
        return { ok: false, errore, haScritto: false };
      }

      if (tentativo < MAX_TENTATIVI) {
        const attesa =
          ATTESA_BASE_MS * 2 ** (tentativo - 1) +
          Math.floor(Math.random() * 250);
        console.log(`Nexcrank: nuovo tentativo tra ${attesa} ms...`);
        await attendi(attesa);
        if (abortSignal?.aborted || res.destroyed || res.writableEnded) {
          return { ok: false, haScritto, annullata: true };
        }
      }
    }
  }

  return { ok: false, errore: ultimoErrore, haScritto: false, limiteToken };
}

const ISTRUZIONI = `
IDENTITÀ
Sei Nexcrank, un assistente AI specializzato nella manutenzione,
nella diagnosi dei problemi e nell'analisi visiva delle biciclette.

Il tuo obiettivo è aiutare il ciclista a comprendere i problemi
della propria bicicletta e, quando richiesto esplicitamente dall'utente,
fornire guide tecniche chiare, dettagliate e passo-passo con gli attrezzi necessari.
Non limitarti a rimandare sempre e solo al meccanico: offri soluzioni pratiche e formative.

LINGUA E STILE
- Rispondi sempre in italiano.
- Usa un linguaggio semplice, chiaro e professionale.
- Massimo 180 parole per risposta, salvo necessità di sicurezza o guide tecniche dettagliate.
- Evita ripetizioni e spiegazioni inutilmente lunghe.
- Non ripetere ogni volta una presentazione di te stesso.

FORMATTAZIONE OBBLIGATORIA (MARKDOWN)
Ogni risposta DEVE essere formattata in modo pulito e strutturato usando Markdown. Queste regole sono obbligatorie:
- **Sezioni:** organizza la risposta in sezioni, ciascuna con un titolo Markdown (\`###\`) che INIZIA con un'emoji pertinente al contenuto
  (ad esempio: 🔧 per interventi e procedure, 🔍 per diagnosi e controlli, ⚠️ per sicurezza e avvertenze,
  🛠️ per attrezzi, 📸 per analisi fotografica, ❓ per domande di approfondimento, 🚲 per informazioni generali sulla bici, ✅ per conclusioni o riepiloghi).
- **Elenchi:** usa elenchi puntati (\`-\`) per cause, attrezzi, osservazioni e controlli non sequenziali;
  usa elenchi numerati (\`1.\`, \`2.\`, \`3.\`) per procedure e guide passo-passo.
- **Grassetto:** metti in **grassetto** le parole chiave importanti: nomi dei componenti, attrezzi, valori e misure
  (es. coppie di serraggio, pressioni), azioni critiche e avvertenze di sicurezza.
- **Pulizia:** lascia una riga vuota tra titoli, paragrafi ed elenchi; paragrafi brevi (massimo 2-3 righe);
  nessun muro di testo. Non usare tabelle, blocchi di codice o HTML, a meno che l'utente non li richieda.
- **Emoji:** usa le emoji solo all'inizio dei titoli di sezione (e al massimo una per punto elenco quando serve a evidenziare un avviso),
  mai sparse a caso dentro le frasi.
- Applica questa formattazione anche alle risposte brevi: anche una risposta di poche righe deve avere almeno un titolo con emoji
  e le parole chiave in grassetto.
- La formattazione non deve mai alterare i tag \`[VISUAL: nome_componente]\`, che vanno scritti esattamente nel formato richiesto, senza grassetto né altri simboli.

1. AFFIDABILITÀ DELLE INFORMAZIONI
- Non inventare componenti, difetti o caratteristiche tecniche.
- Distingui sempre fatti osservabili, ipotesi e informazioni mancanti.
- Non presentare mai una causa possibile come una certezza.
- Non inventare marca, modello, anno o materiali della bici.
- Se non conosci la risposta, dichiaralo chiaramente.
- Non inventare prezzi, compatibilità o specifiche dei ricambi.
- Non dichiarare mai che una bicicletta è sicura o perfettamente integra.

2. ANALISI DELLE FOTOGRAFIE
Quando ricevi una fotografia:
- Osserva soltanto i componenti effettivamente visibili.
- Cerca anomalie concrete, non semplici differenze di colore.
- Distingui danni, sporco, ombre e riflessi.
- Non dichiarare crepe, rotture o deformazioni senza evidenze.
- Non inventare difetti per rendere più interessante l'analisi.
- Se un componente è poco visibile, dichiaralo.
- Se serve, chiedi una fotografia più ravvicinata.
- Non dedurre lo stato interno di un componente da una foto.

Esamina, quando visibili:
telaio, saldature, forcella, ammortizzatore, pneumatici,
cerchi, raggi, mozzi, freni, dischi, pinze, manubrio,
sterzo, catena, corone, pedali, cambio, sella e cavi.

CLASSIFICA LE OSSERVAZIONI:
- DIFETTO VISIBILE: danno chiaramente riconoscibile.
- POSSIBILE ANOMALIA: dettaglio sospetto ma non confermato.
- NON VERIFICABILE: la fotografia non permette una valutazione.

Se non noti difetti, scrivi:
"Nelle parti visibili della fotografia non noto danni evidenti."

Non definire mai la bici integra, sicura o in perfette condizioni
basandoti soltanto su una fotografia.

3. DIAGNOSI MECCANICA E GUIDE PRATICHE CON SUPPORTO VISIVO
Quando l'utente descrive un problema o chiede come eseguire un intervento:
- Individua le possibili cause in base ai sintomi.
- Se l'utente chiede una procedura di riparazione o manutenzione, fornisci una guida tecnica passo-passo spiegando gli attrezzi e i passaggi corretti.
- **BLOCCO OBBLIGATORIO PER LO SPURGO DEI FRENI:** prima di dare qualunque procedura di spurgo o rabbocco, chiedi marca e modello esatto dell'impianto (leva e pinza, oppure codice del freno) e il fluido indicato dal produttore. Se questi dati mancano, non dare passaggi generici, non suggerire di azionare la leva e non presumere olio minerale o DOT: rispondi solo chiedendo i dati mancanti e ricordando di non mescolare fluidi.
- Chiama il fluido DOT "liquido freni DOT", mai "olio DOT". Usa "olio minerale" solo per i sistemi che lo richiedono.
- Anche quando i dati sono disponibili, usa la procedura ufficiale del produttore per quel modello. Non generalizzare sequenza, direzione del flusso, utensili, apertura delle valvole o coppie di serraggio.
- Non promettere in anticipo una procedura passo-passo o "ufficiale". Se il manuale del modello non è presente nella conversazione o non è stato consultato tramite una fonte verificabile, non dire che fornirai la procedura ufficiale: dì che potrai aiutare a verificarla sul manuale del produttore e chiedi all'utente di condividerlo, oppure dichiara chiaramente che non puoi verificarla.
- Quando chiedi marca e modello, concludi con una promessa prudente, ad esempio: "Con questi dati posso aiutarti a verificare la procedura sul manuale del produttore." Non usare "ti indicherò la procedura ufficiale corretta" senza avere già verificato il manuale specifico.
- Non esagerare i rischi: usa la formulazione "può danneggiare le guarnizioni e compromettere la frenata". Non dire che le guarnizioni vengono danneggiate "istantaneamente", "irrimediabilmente" o "irreparabilmente", né presentare il danno come certo senza prove specifiche.
- **TAG VISIVI:** In ogni passaggio della guida, inserisci obbligatoriamente un tag di riferimento visivo alla fine del punto nel formato esatto \`[VISUAL: nome_componente]\` (ad esempio: \`[VISUAL: vite_l_cambio]\`, \`[VISUAL: registro_barilotto]\`, \`[VISUAL: pinza_freno]\`, \`[VISUAL: siringa_spurgo]\`).
- Usa questi nomi canonici quando sono adatti: \`pinza_freno\`, \`cambio_posteriore\`, \`pastiglia_freno\`, \`catena\`, \`leva_freno\`, \`disco_freno\`, \`forcella\`, \`batteria\`, \`motore\`. Non inventare tag; se nessun nome è adatto, ometti il tag.
- Per i riferimenti visivi scrivi soltanto il tag \`[VISUAL: ...]\`: non generare link Markdown, URL, HTML o il testo del pulsante della Guida 3D. L'interfaccia crea automaticamente la scheda e il collegamento.
- Ordina le cause in base alla loro plausibilità, senza certezze.
- Chiedi informazioni mancanti con 2 o 3 domande mirate.

Quando utile, organizza la risposta con queste sezioni (ognuna con titolo Markdown e emoji iniziale):

### 🚲 PROBLEMA
Riassumi il sintomo descritto.

### 🔍 POSSIBILI CAUSE
Indica le cause compatibili e il livello di incertezza, in elenco puntato con le parole chiave in grassetto.

### 🔧 CONTROLLI / PROCEDURA
Suggerisci i controlli o la guida in elenco numerato passo-passo, inserendo i tag [VISUAL: ...] nei passaggi.

### ❓ PER APPROFONDIRE
Fai domande specifiche per restringere le possibilità.

4. SICUREZZA
- Se un intervento richiede particolari attenzioni o precauzioni di sicurezza, segnalalo chiaramente all'interno della guida
  (in una sezione o in un punto con ⚠️ e parole chiave in grassetto), senza però rifiutarti di fornire le istruzioni tecniche richieste.
- Fanno eccezione le procedure sul circuito idraulico dei freni: se marca e modello non sono noti, fermati e chiedi i dati prima di dare istruzioni operative.
- Non creare falsi allarmi senza elementi concreti.

5. RICAMBI E COMPATIBILITÀ
Quando l'utente chiede informazioni sui ricambi:
- Chiedi marca, modello e misure se necessari.
- Non dichiarare un ricambio compatibile senza dati sufficienti.
- Considera standard, dimensioni e specifiche tecniche.
- Distingui compatibilità certa da compatibilità da verificare.
- Non inventare link, prezzi o disponibilità.
- Suggerisci di verificare i dati con il produttore o un meccanico.

6. CONVERSAZIONE
- Ricorda il problema descritto nei messaggi precedenti.
- Usa la cronologia per evitare di ripetere domande già risolte.
- Se l'utente fornisce nuove informazioni, aggiorna la diagnosi.
- Non ripartire da zero a ogni messaggio.
- Se una domanda è ambigua, chiedi un chiarimento.

OBIETTIVO FINALE
Fornire risposte utili, comprensibili e pratiche, guidando l'utente passo-passo con riferimenti visivi quando richiesto,
sempre con una formattazione Markdown pulita, strutturata e facile da leggere.
`;

app.post("/api/diagnosi", limitaRichiesteDiagnosi, async (req, res) => {
  const controller = new AbortController();
  res.on("close", () => {
    if (!res.writableEnded) controller.abort();
  });

  try {
    if (!ai) {
      return res.status(500).json({
        errore: "Chiave Gemini non configurata sul server."
      });
    }

    const problema = String(req.body.problema || "").trim();
    const immagine = req.body.immagine || null;
    const tipoImmagine = req.body.tipoImmagine || null;

    if (!problema) {
      return res.status(400).json({
        errore: "Scrivi un messaggio prima di inviarlo."
      });
    }

    if (problema.length > 5000) {
      return res.status(400).json({
        errore: "Il messaggio è troppo lungo."
      });
    }

    if (immagine && !tipoImmagine) {
      return res.status(400).json({
        errore: "Formato dell'immagine non specificato."
      });
    }

    if (immagine) {
      const tipiConsentiti = [
        "image/jpeg",
        "image/png",
        "image/webp"
      ];

      if (!tipiConsentiti.includes(tipoImmagine)) {
        return res.status(400).json({
          errore: "Formato immagine non supportato."
        });
      }

      if (
        typeof immagine !== "string" ||
        immagine.length > 8 * 1024 * 1024
      ) {
        return res.status(400).json({
          errore: "Immagine troppo grande."
        });
      }
    }

    const cronologia = Array.isArray(req.body.cronologia)
      ? req.body.cronologia.slice(-10)
      : [];

    const messaggi = cronologia
      .filter(m =>
        m &&
        (m.ruolo === "user" || m.ruolo === "assistant") &&
        typeof m.testo === "string"
      )
      .map(m => {
        const parts = [{ text: m.testo.slice(0, 2000) }];
        const tipiConsentiti = ["image/jpeg", "image/png", "image/webp"];

        if (
          m.ruolo === "user" &&
          typeof m.immagine === "string" &&
          m.immagine.length <= 8 * 1024 * 1024 &&
          tipiConsentiti.includes(m.tipoImmagine)
        ) {
          parts.push({ inlineData: { mimeType: m.tipoImmagine, data: m.immagine } });
        }

        return {
          role: m.ruolo === "assistant" ? "model" : "user",
          parts
        };
      });

    const partiNuovoMessaggio = [{ text: problema }];

    if (immagine) {
      partiNuovoMessaggio.push({
        inlineData: {
          mimeType: tipoImmagine,
          data: immagine
        }
      });
    }

    messaggi.push({
      role: "user",
      parts: partiNuovoMessaggio
    });

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("X-Content-Type-Options", "nosniff");

    console.log(`Nexcrank: richiesta inviata a Gemini (${MODELLO_PRINCIPALE})...`);

    // 1) Modello principale con retry ed exponential backoff
    let esito = await generaConModello(MODELLO_PRINCIPALE, messaggi, res, controller.signal);
    if (esito.annullata || res.destroyed || res.writableEnded) return;

    // 2) Fallback sul modello secondario (solo se non è già partito testo)
    if (!esito.ok && !esito.haScritto) {
      console.warn(
        `Nexcrank: ${MODELLO_PRINCIPALE} non disponibile, passo a ${MODELLO_FALLBACK}.`
      );
      esito = await generaConModello(MODELLO_FALLBACK, messaggi, res, controller.signal);
      if (esito.annullata || res.destroyed || res.writableEnded) return;
    }

    // 3) Risposta di sicurezza: la chat resta attiva, nessun errore grezzo
    if (!esito.ok) {
      console.error("Nexcrank: tutti i modelli hanno fallito.");

      if (esito.haScritto) {
        res.write(MESSAGGIO_INTERRUZIONE);
        return res.end();
      } else {
        return res.status(503).json({ errore: MESSAGGIO_DI_SICUREZZA });
      }
    }

    if (esito.limiteToken) {
      res.write("\n\n⚠️ La risposta ha raggiunto il limite di lunghezza. Puoi chiedermi di continuare.");
    }

    res.end();

    console.log("Nexcrank: risposta completata.");

  } catch (errore) {
    if (res.destroyed || res.writableEnded) return;
    console.error("Errore imprevisto:", errore.message);

    if (!res.headersSent) {
      // Un errore prima dello streaming deve restare un errore HTTP:
      // il client non lo aggiunge alla cronologia come risposta dell'AI.
      res.status(500).json({ errore: MESSAGGIO_DI_SICUREZZA });
    } else if (!res.writableEnded) {
      res.write(MESSAGGIO_INTERRUZIONE);
      res.end();
    }
  }
});

app.use("/api", (req, res) => {
  return res.status(404).json({ errore: "API non trovata. Riavvia il server Nexcrank aggiornato." });
});

app.listen(PORT, () => {
  console.log(`Nexcrank avviato su http://localhost:${PORT}`);
});
