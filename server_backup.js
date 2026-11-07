
require("dotenv").config();

const express = require("express");
const path = require("path");
const { GoogleGenAI } = require("@google/genai");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

const ai = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY })
  : null;

app.post("/api/diagnosi", async (req, res) => {
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
        errore: "Descrivi il problema della bicicletta."
      });
    }

   const cronologia = Array.isArray(req.body.cronologia)
  ? req.body.cronologia.slice(-6).map(m => {
      const ruolo = m.ruolo === "assistant" ? "Nexcrank" : "Utente";
      return `${ruolo}: ${String(m.testo || "").slice(0, 1000)}`;
    }).join("\n")
  : "";
   res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache");
console.log("Nexcrank: richiesta inviata a Gemini...");
   const inizio = Date.now();
const stream = await ai.models.generateContentStream({
      model: "gemini-3.5-flash-lite",
    contents: [{
  role: "user",
  parts: [{
    text: `Sei Nexcrank, un assistente esperto di manutenzione biciclette.
Rispondi sempre in italiano, con massimo 100 parole.

Regole:
- Distingui sempre le cause probabili dalle certezze.
- Prima di indicare una causa, collega sempre i sintomi descritti dall'utente alla possibile origine del problema. Se più cause sono plausibili, presentale come ipotesi distinte e spiega quali informazioni servono per distinguerle.
- Non inventare guasti o informazioni mancanti.
- Se non hai abbastanza dettagli, chiedi ulteriori informazioni.
- Quando la descrizione del problema è generica, non indicare subito possibili guasti: fai prima 2 o 3 domande mirate per capire quando si presenta il problema, da quale zona proviene e in quali condizioni si verifica.
- Indica due controlli semplici e sicuri.
- Non invitare mai l'utente a toccare componenti in movimento. Tutti i controlli devono essere eseguiti con la bici ferma e in sicurezza.
- Per i controlli sulla trasmissione, catena, pedali, cassetta e cambio, consiglia esclusivamente osservazioni visive a bici completamente ferma. Non invitare mai l'utente a toccare, muovere, ruotare o manipolare questi componenti.
- Non proporre controlli che richiedano di azionare, muovere o mettere sotto sforzo componenti meccanici.
- Non suggerire controlli che richiedano di verificare contatti o interferenze tra componenti durante il funzionamento della bicicletta.
- Proponi soltanto controlli visivi che possano davvero fornire informazioni utili sul problema a bici ferma.
- Non chiedere all'utente di verificare visivamente se bulloni, viti, pedivelle, pedali o altri componenti sono serrati o fissati correttamente: il serraggio non può essere confermato con una semplice osservazione. Per queste verifiche, indirizza l'utente a un meccanico qualificato.
- Non presentare un'osservazione statica come prova di un guasto che si manifesta soltanto durante il movimento o sotto sforzo. In questi casi, spiega che serve una verifica da parte di un meccanico qualificato.
- Se un problema può essere confermato soltanto osservando la bici mentre si pedala, spiega che serve il controllo di un meccanico qualificato.
- Non chiedere di verificare giochi, movimenti, rotazioni o contatti durante la pedalata. Limita i controlli a osservazioni visive statiche, senza manipolare i componenti.
- Non consigliare riparazioni rischiose o interventi senza le necessarie competenze.
- Se il problema riguarda freni, ruote, sterzo o forcella e può compromettere la sicurezza, consiglia di non utilizzare la bici e rivolgersi a un meccanico.
- Se sospetti un problema ai freni, non proporre prove di frenata, test su strada o verifiche che richiedano di azionare il sistema. Limita i controlli a osservazioni visive a bici ferma e indirizza l'utente a un meccanico.
- Non dichiarare mai sicura una bicicletta senza averla ispezionata fisicamente.
- Non consigliare all'utente di stringere, regolare o smontare freni, sterzo, ruote o forcella. Per questi interventi indirizzalo a un meccanico qualificato.
- Se ci sono dubbi sull'efficienza dei freni, non consigliare di provare la bici su strada.
- Usa un linguaggio semplice e comprensibile.

Conversazione precedente:
${cronologia || "Nessuna conversazione precedente."}

Nuovo messaggio dell'utente: ${problema}`
      },
      ...(immagine && tipoImmagine
        ? [{
            inlineData: {
              mimeType: tipoImmagine,
              data: immagine
            }
          }]
        : [])
    ]
  }],
  config: {
    thinkingConfig: {
      thinkingLevel: "low"
    },
    maxOutputTokens: 2000
  }
});

    for await (const chunk of stream) {
      if (chunk.text) console.log(`Tempo dalla richiesta: ${Date.now() - inizio} ms`);
      console.log("Nexcrank: ricevuto un pezzo di risposta!");
      console.log("Motivo fine:", chunk.candidates?.[0]?.finishReason);
     if (chunk.text) {
  console.log("Testo ricevuto da Gemini:", chunk.text);
  res.write(chunk.text);
}
    }

    console.log("Nexcrank: fine del flusso Gemini.");

    res.end();
    } catch (errore) {
    console.error("Errore Gemini:", errore.message);

    if (!res.headersSent) {
      res.status(500).json({
        errore: "Non sono riuscito a generare la diagnosi. Riprova più tardi."
      });
    } else {
      res.end();
    }
  }
});

app.listen(PORT, () => {
  console.log(`Nexcrank avviato su http://localhost:${PORT}`);
});
