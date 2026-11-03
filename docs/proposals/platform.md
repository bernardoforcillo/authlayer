# Proposta: da authlayer a piattaforma di sviluppo prodotto end-to-end

> Stato: **bozza da discutere**. Nessun codice è stato cambiato. Questo
> documento serve a fissare la direzione prima di toccare l'API pubblica.

## 1. L'idea in una frase

Un **companion per lo sviluppo multipiattaforma**: chi costruisce un prodotto
digitale (web, mobile, desktop, agenti) lo usa dalla prima riga di codice fino
alla produzione, senza riscrivere ogni volta le stesse fondamenta — identità,
accessi, piani, flag, notifiche, eventi, conformità.

authlayer oggi risolve bene **un** pezzo di quella catena (chi sei e cosa puoi
fare). La proposta è allargarlo a tutta la catena, mantenendo gli stessi
principi che lo rendono solido:

- **dichiarativo nel codice** (come gli statement RBAC);
- **porte di storage astratte** con implementazione in memoria e Postgres
  (`store/memory`, `store/drops`);
- **hook ed eventi** su ogni operazione;
- **audit e privacy di serie**, non come aggiunta;
- **suite di conformità** (`*test`) per ogni porta.

## 2. Il ciclo di vita del prodotto e cosa c'è già

| Fase | Domanda dello sviluppatore | Oggi in authlayer | Manca |
|---|---|---|---|
| **Avvio** | Come parto senza boilerplate? | `examples/` | CLI di scaffolding, template per piattaforma |
| **Identità** | Chi è l'utente? | `auth`, `auth/passkey`, `auth/magiclink`, `oauth`, `token`, `password` | SDK client (web, iOS, Android, Flutter) |
| **Accessi** | Cosa può fare? | `access`, `scope`, `org`, `team`, `invite`, `apikey` | Valutazione lato client (permessi nel token/SDK) |
| **Monetizzazione** | Cosa ha pagato? | — | Piani, entitlement per scope, adapter provider pagamenti |
| **Rilascio** | Chi vede la nuova funzione? | — | Feature flag e rollout per utente/org/team |
| **Comunicazione** | Come lo avviso? | (le email sono a carico del chiamante) | Notifiche: template, canali, preferenze |
| **Integrazione** | Come lo sanno gli altri sistemi? | `hooks` interni | Webhook in uscita firmati, con retry |
| **Conformità** | Cosa è successo e chi ha acconsentito? | `audit`, `consent`, `privacy` | Esportazioni e dashboard |
| **Operatività** | Come lo gestisco? | — | Console admin, API HTTP pronta |

La colonna "Oggi" è la base. Più di metà della catena c'è già, ed è la parte
più difficile da fare bene.

## 3. Architettura proposta

```
              ┌──────────────── SDK client ────────────────┐
              │  TypeScript · Swift · Kotlin · Dart/Flutter │
              └──────────────────────┬──────────────────────┘
                                     │ HTTP/JSON (+ OpenAPI)
┌────────────────────────────────────┴────────────────────────────────────┐
│ server/  — handler HTTP montabili (net/http), oppure binario standalone │
├──────────────────────────────────────────────────────────────────────────┤
│ moduli di dominio (librerie Go, come oggi)                               │
│  auth · access/scope/org/team · apikey · oauth · invite      ← esistenti │
│  billing · flags · notify · webhook                          ← nuovi     │
├──────────────────────────────────────────────────────────────────────────┤
│ core · hooks/eventi · audit · consent · privacy              ← trasversali│
├──────────────────────────────────────────────────────────────────────────┤
│ store/memory · store/drops (Postgres)                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

Scelte chiave:

1. **La libreria resta il cuore.** Chi oggi importa authlayer non si rompe: i
   nuovi moduli si aggiungono accanto, ognuno opzionale.
2. **Un solo contesto.** Flag, entitlement e notifiche ricevono lo stesso
   `scope`/principal che usa l'RBAC. "Questa org ha il piano Pro *e* il flag
   `new-editor` *e* il permesso `doc:update`" diventa una sola domanda.
3. **Gli eventi sono la colla.** Ogni modulo emette eventi già tipizzati
   (come gli hook attuali); webhook, notifiche e audit sono consumatori di
   quegli eventi, non logica duplicata.
4. **HTTP opzionale e sottile.** `server/` espone i moduli come handler
   montabili e genera uno schema OpenAPI. Dallo schema si generano gli SDK
   multipiattaforma, così web e mobile restano allineati per costruzione.

## 4. Milestone

Ogni milestone è rilasciabile da sola e non rompe le precedenti.

| # | Contenuto | Perché in quest'ordine |
|---|---|---|
| **M5** | `server/`: handler HTTP per auth, sessioni, org, inviti + OpenAPI | Sblocca tutto il lato multipiattaforma; riusa solo codice esistente |
| **M6** | SDK TypeScript generato + esempio web end-to-end | Primo client reale; valida lo schema |
| **M7** | `flags`: flag e rollout valutati sul contesto scope | Piccolo, usa l'RBAC esistente, valore immediato |
| **M8** | `webhook` + `notify` sopra gli eventi | Rende il prodotto integrabile |
| **M9** | `billing`: piani ed entitlement, adapter per un provider | Il modulo più delicato, dopo che eventi e webhook sono stabili |
| **M10** | SDK Swift/Kotlin/Dart + CLI di scaffolding | Completa il "multipiattaforma" |
| **M11** | Console admin | Interfaccia sopra API ormai stabili |

## 5. Decisioni aperte

- **Nome.** "authlayer" descrive solo il primo modulo. Rinominare il modulo Go
  è un cambiamento incompatibile; si può rimandare a M10 o a una v1.
- **Repo unico o più repo.** Gli SDK in altri linguaggi probabilmente vanno in
  repo separati; i moduli Go possono restare qui.
- **Provider di pagamento** per M9 (es. Stripe, Paddle, Lemon Squeezy).
- **Hosted o solo self-hosted.** Questa proposta copre il self-hosted; un
  servizio gestito si può costruire sopra senza cambiare l'architettura.

## 6. Primo passo concreto

Avviare **M5**: un pacchetto `server/` che espone come handler `net/http`,
con test, gli endpoint di registrazione, login, refresh, logout, utente
corrente e gestione org. Non tocca le API esistenti e rende authlayer
utilizzabile subito da qualsiasi client, su qualsiasi piattaforma.
