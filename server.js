require("dotenv").config();

const express = require("express");
const path = require("path");
const cors = require("cors");
const { initializeApp, cert, applicationDefault } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { GoogleGenAI } = require("@google/genai");

const app = express();
const PORT = process.env.PORT || 3000;
app.set("trust proxy", 1);
app.disable("x-powered-by");

// ---------------------------------------------------------------------------
// FIREBASE ADMIN (fail-closed: senza credenziali valide il server NON parte)
// ---------------------------------------------------------------------------
// Fornisci UNA di queste opzioni (su Render: Environment, oppure nel file .env):
//  - FIREBASE_SERVICE_ACCOUNT: JSON del service account (oppure il JSON in base64)
//  - GOOGLE_APPLICATION_CREDENTIALS: percorso del file JSON del service account
function leggiServiceAccount() {
  let raw = String(process.env.FIREBASE_SERVICE_ACCOUNT || "").trim();
  if (!raw) return null;

  // Supporta anche il JSON codificato in base64
  if (!raw.startsWith("{") && !raw.startsWith('"')) {
    try {
      raw = Buffer.from(raw, "base64").toString("utf8").trim();
    } catch {
      /* si prosegue con il valore originale */
    }
  }

  const analizza = testo => JSON.parse(testo);
  let account;
  try {
    account = analizza(raw);
  } catch {
    // Ritorni a capo reali dentro private_key (incollati su più righe):
    // si trasformano in \n escapati e si riprova.
    const riparato = raw.replace(
      /("private_key"\s*:\s*")([\s\S]*?)("\s*[,}])/,
      (_, a, chiave, c) => a + chiave.replace(/\r?\n/g, "\\n") + c
    );
    try {
      account = analizza(riparato);
    } catch {
      throw new Error("FIREBASE_SERVICE_ACCOUNT non è un JSON valido.");
    }
  }

  // JSON racchiuso tra virgolette (doppia serializzazione)
  if (typeof account === "string") account = analizza(account);

  if (!account || typeof account !== "object") {
    throw new Error("FIREBASE_SERVICE_ACCOUNT non contiene un oggetto valido.");
  }

  // Normalizza i "\n" letterali della chiave privata in veri a capo
  if (typeof account.private_key === "string") {
    account.private_key = account.private_key.replace(/\\n/g, "\n");
  }

  for (const campo of ["project_id", "client_email", "private_key"]) {
    if (!account[campo]) {
      throw new Error(`FIREBASE_SERVICE_ACCOUNT: campo "${campo}" mancante.`);
    }
  }
  return account;
}

function inizializzaFirebase() {
  const account = leggiServiceAccount();

  if (account) {
    initializeApp({ credential: cert(account) });
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    initializeApp({ credential: applicationDefault() });
  } else {
    throw new Error(
      "Imposta FIREBASE_SERVICE_ACCOUNT oppure GOOGLE_APPLICATION_CREDENTIALS."
    );
  }
}

try {
  inizializzaFirebase();
} catch (errore) {
  console.error("Nexcrank: Firebase Admin non inizializzato, avvio annullato:", errore.message);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// SICUREZZA DI BASE: header, CORS
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  if (req.secure) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

// Elenco di origini autorizzate, separate da virgola. Esempio:
// ALLOWED_ORIGINS=https://tuodominio.it,http://localhost:3000
const originiConsentite = String(process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(o => o.trim().replace(/\/+$/, ""))
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    // Richieste senza Origin (stessa origine, curl, ecc.): l'accesso alle rotte
    // riservate richiede comunque un token Firebase valido.
    if (!origin) return callback(null, true);
    return callback(null, originiConsentite.includes(origin));
  },
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 600
}));

app.use(express.static(path.join(__dirname, "public"), { dotfiles: "ignore" }));

// ---------------------------------------------------------------------------
// RATE LIMIT (in memoria; con più processi va sostituito con uno store condiviso)
// ---------------------------------------------------------------------------
function creaLimitatore({ finestraMs, massimo, chiave, messaggio }) {
  const registro = new Map();

  setInterval(() => {
    const ora = Date.now();
    for (const [k, v] of registro) {
      if (ora - v.inizio >= finestraMs) registro.delete(k);
    }
  }, Math.min(finestraMs, 60 * 1000)).unref();

  return (req, res, next) => {
    const ora = Date.now();
    const id = chiave(req);
    let record = registro.get(id);

    if (!record || ora - record.inizio >= finestraMs) {
      record = { inizio: ora, conteggio: 0 };
    }
    record.conteggio += 1;
    registro.set(id, record);

    res.setHeader("RateLimit-Limit", String(massimo));
    res.setHeader("RateLimit-Remaining", String(Math.max(0, massimo - record.conteggio)));

    if (record.conteggio > massimo) {
      const retryDopo = Math.ceil((record.inizio + finestraMs - ora) / 1000);
      res.setHeader("Retry-After", String(Math.max(1, retryDopo)));
      return res.status(429).json({ errore: messaggio });
    }
    next();
  };
}

const ipRichiesta = req => req.ip || req.socket.remoteAddress || "sconosciuto";

// Prima dell'autenticazione: protegge dai tentativi ripetuti con token fittizi.
const limitaPerIp = creaLimitatore({
  finestraMs: 15 * 60 * 1000,
  massimo: 120,
  chiave: ipRichiesta,
  messaggio: "Troppe richieste. Riprova tra qualche minuto."
});

// Dopo l'autenticazione: limite per singolo utente (protegge i costi Gemini).
const limitaDiagnosiPerUtente = creaLimitatore({
  finestraMs: 15 * 60 * 1000,
  massimo: 20,
  chiave: req => `uid:${req.utente.uid}`,
  messaggio: "Hai inviato troppe richieste. Riprova tra qualche minuto."
});

// ---------------------------------------------------------------------------
// AUTENTICAZIONE FIREBASE
// ---------------------------------------------------------------------------
function rifiuta(res, stato, errore) {
  res.setHeader("Cache-Control", "no-store");
  if (stato === 401) res.setHeader("WWW-Authenticate", 'Bearer realm="nexcrank"');
  return res.status(stato).json({ errore });
}

/**
 * Consente l'accesso SOLO con un ID token Firebase valido:
 *  - firma, scadenza, issuer e audience verificati da verifyIdToken;
 *  - token non revocato (checkRevoked) e utente esistente e non disabilitato;
 *  - email presente e verificata, account non anonimo.
 * Qualsiasi anomalia produce 401 (credenziali assenti/non valide) o 403 (non autorizzato).
 */
async function richiediAutenticazione(req, res, next) {
  const intestazione = String(req.headers.authorization || "");
  const corrispondenza = /^Bearer\s+([A-Za-z0-9\-_.]+)$/.exec(intestazione);
  if (!corrispondenza || corrispondenza[1].length > 4096) {
    return rifiuta(res, 401, "Autenticazione richiesta.");
  }

  let token;
  try {
    token = await getAuth().verifyIdToken(corrispondenza[1], true);
  } catch (errore) {
    const codice = String(errore?.code || "");
    if (codice === "auth/user-disabled") {
      return rifiuta(res, 403, "Account disabilitato.");
    }
    if (codice.startsWith("auth/")) {
      // Token scaduto, revocato, malformato, firmato male, utente inesistente...
      return rifiuta(res, 401, "Sessione non valida o scaduta. Accedi di nuovo.");
    }
    // Problema infrastrutturale: si nega comunque l'accesso (fail-closed).
    console.error("Nexcrank: verifica token Firebase non riuscita:", errore?.message);
    return rifiuta(res, 503, "Servizio di autenticazione temporaneamente non disponibile.");
  }

  if (!token.uid || !token.email) {
    return rifiuta(res, 403, "Account senza email: accesso non consentito.");
  }
  if (token.firebase?.sign_in_provider === "anonymous") {
    return rifiuta(res, 403, "Gli account anonimi non sono ammessi.");
  }
  if (token.email_verified !== true) {
    return rifiuta(res, 403, "Verifica il tuo indirizzo email prima di continuare.");
  }

  req.utente = { uid: token.uid, email: String(token.email).toLowerCase() };
  next();
}

// Utile al frontend per controllare la sessione.
app.get("/api/auth/me", limitaPerIp, richiediAutenticazione, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.json({ utente: req.utente });
});

// ---------------------------------------------------------------------------
// GEMINI
// ---------------------------------------------------------------------------
const ai = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY })
  : null;

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

// ---------------------------------------------------------------------------
// ROTTA PROTETTA: DIAGNOSI
// Ordine: limite per IP -> autenticazione Firebase -> limite per utente -> parsing JSON.
// Il body (fino a 18 MB) viene letto solo DOPO la verifica del token.
// ---------------------------------------------------------------------------
const TIPI_IMMAGINE_CONSENTITI = ["image/jpeg", "image/png", "image/webp"];
const MAX_IMMAGINE = 8 * 1024 * 1024;

app.post(
  "/api/diagnosi",
  limitaPerIp,
  richiediAutenticazione,
  limitaDiagnosiPerUtente,
  express.json({ limit: "18mb" }),
  async (req, res) => {
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

      const corpo = req.body && typeof req.body === "object" ? req.body : {};
      const problema = String(corpo.problema || "").trim();
      const immagine = corpo.immagine || null;
      const tipoImmagine = corpo.tipoImmagine || null;

      if (!problema) {
        return res.status(400).json({ errore: "Scrivi un messaggio prima di inviarlo." });
      }

      if (problema.length > 5000) {
        return res.status(400).json({ errore: "Il messaggio è troppo lungo." });
      }

      if (immagine && !tipoImmagine) {
        return res.status(400).json({ errore: "Formato dell'immagine non specificato." });
      }

      if (immagine) {
        if (!TIPI_IMMAGINE_CONSENTITI.includes(tipoImmagine)) {
          return res.status(400).json({ errore: "Formato immagine non supportato." });
        }
        if (typeof immagine !== "string" || immagine.length > MAX_IMMAGINE) {
          return res.status(400).json({ errore: "Immagine troppo grande." });
        }
      }

      const cronologia = Array.isArray(corpo.cronologia)
        ? corpo.cronologia.slice(-10)
        : [];

      const messaggi = cronologia
        .filter(m =>
          m &&
          (m.ruolo === "user" || m.ruolo === "assistant") &&
          typeof m.testo === "string"
        )
        .map(m => {
          const parts = [{ text: m.testo.slice(0, 2000) }];

          if (
            m.ruolo === "user" &&
            typeof m.immagine === "string" &&
            m.immagine.length <= MAX_IMMAGINE &&
            TIPI_IMMAGINE_CONSENTITI.includes(m.tipoImmagine)
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
          inlineData: { mimeType: tipoImmagine, data: immagine }
        });
      }

      messaggi.push({ role: "user", parts: partiNuovoMessaggio });

      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Content-Type-Options", "nosniff");

      console.log(`Nexcrank: richiesta di ${req.utente.uid} inviata a Gemini (${MODELLO_PRINCIPALE})...`);

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
        }
        return res.status(503).json({ errore: MESSAGGIO_DI_SICUREZZA });
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
  }
);

// ---------------------------------------------------------------------------
// FALLBACK E GESTIONE ERRORI (nessuna informazione interna nelle risposte)
// ---------------------------------------------------------------------------
app.use("/api", (req, res) => {
  return res.status(404).json({ errore: "API non trovata." });
});

app.use((errore, req, res, next) => {
  if (res.headersSent) return next(errore);
  if (errore?.type === "entity.too.large") {
    return res.status(413).json({ errore: "Richiesta troppo grande." });
  }
  if (errore?.type === "entity.parse.failed") {
    return res.status(400).json({ errore: "Richiesta non valida." });
  }
  console.error("Nexcrank: errore non gestito:", errore?.message);
  return res.status(500).json({ errore: "Errore interno del server." });
});

app.listen(PORT, () => {
  console.log(`Nexcrank avviato su http://localhost:${PORT}`);
});