# QMandate

QMandate is a post quantum authority layer for AI agents. It proves which person or organisation authorised an agent, exactly what the agent was permitted to do, within which limits and for how long, and that every action the agent took stayed inside that authority. Every mandate and every action is signed with the Module Lattice Digital Signature Algorithm, parameter set 65, as standardised in FIPS 204, and each can carry a Qstamp time proof recorded on the Quantova network.

## What QMandate is

An AI agent that pays suppliers, approves refunds, moves funds or answers customers acts on behalf of an organisation. When something goes wrong, three questions decide liability. Who authorised the agent. What exactly was it permitted to do. And did this action fall inside that permission at the moment it happened.

QMandate answers all three with cryptographic evidence. A principal, such as a treasury officer, a business unit or the organisation itself, signs a mandate that names one agent key and lists the permitted actions, the currency and limit of each, the counterparties the agent may deal with and the period the mandate is in force. The agent signs every action it takes, and each action names the exact mandate it relies on. A verifier, whether an auditor, a regulator, a payment provider or a court, can then confirm that the action was taken by that agent, under that mandate, within its limits and before any revocation, without trusting the agent or the organisation, and the time of each record counts as proven only through a finality certificate of the network validators or official endpoints of two independent operators, never through one endpoint alone.

QMandate is standalone. It runs on the systems of the organisation, holds its keys locally and uses the Quantova network only as a neutral public ledger for time proofs.

## Why organisations need it

Agents now initiate payments and decisions at a speed and volume that no human approval process can follow. Payment law requires every payment to be authorised and attributable. Conduct rules require firms to show what was decided and on whose authority. The European Union AI Act, the guidelines of the Monetary Authority of Singapore on AI risk management and the record keeping rules of banking supervisors all expect firms to evidence how automated systems were controlled.

Logs written by the agent platform itself cannot carry that weight, because the platform can alter them and because nothing in them proves that a limit existed before the action was taken. Card networks and payment providers have begun to introduce agent payment protocols, but these are tied to a single network and rely on classical signatures that a quantum computer will be able to forge.

QMandate gives a network neutral, post quantum record of authority and conduct that remains provable for the full retention period of the records it supports.

## Who uses it

1. Banks and payment firms that let agents initiate transfers, refunds or collections within set limits.
2. Treasury and finance teams that delegate supplier payments and reconciliations to agents.
3. Insurers that let agents settle claims below a threshold.
4. Platforms that run agents on behalf of many client organisations and must show each client what its agents were allowed to do.
5. Customer service operations that let agents issue credits, refunds or commitments.
6. Auditors, regulators and payment providers that need to confirm that a given agent action was authorised.

## How an organisation integrates QMandate

1. Give every agent its own key. Each agent receives an ML-DSA-65 key created with the keygen command or the generateKey function and held only by the runtime of that agent. Agents never share keys.

2. Give every approving authority its own key. The principal key belongs to the person or function that is accountable for the agent, and is held in the secrets manager or hardware protected store of the organisation.

3. Grant a mandate. The principal signs a mandate naming the agent key, each permitted action with its currency, its limit per action and its total limit, the permitted counterparties if any, and the period of validity. Amounts are whole numbers of minor units, so 150000 in US dollars means 1,500.00 dollars. The mandate is anchored on the Quantova network before the agent first uses it, which proves that the authority existed before any action taken under it.

4. Check early if it helps, but only as advice. The application may call authorise with the mandate, the intended action, the spend ledger of the agent or the amount already spent under the mandate, and any revocations it holds. The call reads the time of the chain and returns a promise of allowed or refused with the reasons, so an agent can explain a refusal before it prepares an action. authorise is advisory. It reads the spend ledger without holding it, so concurrent calls can all be allowed against the same total, and its answer must never gate a payment or any other action that cannot be undone. Only act, in step 5, decides whether an action may run. A caller may give a time for the decision only within five minutes of the time of the chain, and the amount already spent is never assumed to be 0. The result marks a time given by the caller with atSupplied and reports the time of the chain in chainTime.

5. Sign every action before it runs. act is the gate. The agent calls act before the tool runs, and the tool runs only when act returns a signed action, which it then carries as its instruction. When act refuses, with the code QMANDATE_NOT_AUTHORISED and the reasons, the tool never runs. act signs an action statement with the action, the amount, the currency, the counterparty and a fingerprint of the private details such as an invoice or a payment instruction. The details themselves never leave the organisation. Every action carries its number within its scope, the reference of the previous action of that scope and the running total including itself, all under the signature of the agent. act keeps these in a spend ledger, a folder or a store with an atomic compare and swap, and locks it so that concurrent calls from one or many processes can never sign actions that together exceed the total limit. Because the amount counts toward the total as soon as act signs, concurrent tool calls can never move more than the total limit between them. When a tool fails after act has signed, its action still counts toward the total, so a failure can only lower what the agent may still spend and never raise it, and the application records the failure beside the action. act writes the signed action durably to a journal kept beside the ledger in the same step that moves the ledger on, and ledgerActions returns every recorded action of a scope under a mandate, so an action is never lost when its caller stops before storing it. A store of your own keeps that guarantee only when its compareAndSwap stores the journal entry it is given in the same transaction as the new state, as the ledger folder does, and the store offers readJournal to read that entry back by its name. QMandate never gives a store a signed action outside that swap, so a store can never hold a signed action that its ledger did not count. The ledger records the agent of the mandate, and an unfinished action signed by any other key is refused rather than counted. Each ledger holds a random identifier, created with its first action and kept in its state, and every action it signs carries that identifier, so actions signed from two different ledgers can be told apart. A ledger state is refused, and nothing is signed, when its journal already records an action at or above the number the state would give next, which is what a state restored from an older copy looks like. recover, which ledgerActions calls, then rebuilds the state from the highest unbroken chain of actions in the journal. Back up the journal and the state together and restore them together. A lock or a claim to break one, left by an agent process on the same host that is no longer running, is removed once it is older than thirty seconds. Where the system reports when a process started, as on Linux and macOS, a lock whose process number now belongs to a different process is treated the same way. Elsewhere such a lock stays in place until it is removed by hand, so a reused process number can never release a lock held by a live agent. QMandate refuses to sign an action that the mandate does not permit or that a supplied revocation has withdrawn. act and authorise know of a revocation only when it is passed to them, so the application supplies every revocation it holds for the mandate on each call, and a revocation it has not received yet cannot stop an action.

6. Anchor on a schedule. A single service with a funded Quantova account anchors new actions in batches. Each action receives its own receipt.

7. Revoke when circumstances change. When an agent is retired, compromised or no longer needed, the principal signs and anchors a revocation. Every action recorded after it is shown to be invalid, and actions recorded before it remain valid.

8. Verify when evidence is needed. The organisation hands the action, the mandate, any revocations and the earlier actions under the same mandate to the party that asks. That party verifies them against the principal key it expects, with the verify command, the library or the independent procedure below. Verification always requires the expected envelope type and the expected principal, so a mandate issued by any other key is rejected and a mandate or revocation can never pass where an action is expected.

9. Keep one spend ledger per agent key. Every process and every host that holds the key of an agent signs through one store with an atomic compare and swap, never through a folder or store of its own, because the limits of a mandate hold only within one ledger. A payment provider passes its own records of the actions it has already executed under the mandate as priorActions, beside those the agent supplies, so actions signed from a second ledger show up as a fork or as a second ledger identifier and verify invalid.

## Integration patterns

1. Agent frameworks. A tool wrapper calls act before any tool that moves money or makes a commitment, and runs the tool only with the signed action that act returns. It may call authorise first to explain a refusal early, but never runs a tool on the answer of authorise alone. Before the tool runs, the wrapper calls consume with the action and the ledger, which records the reference of the action durably in the same step that releases the tool, and a reference already recorded is refused with the code QMANDATE_ALREADY_EXECUTED, so one signed action runs once however often it is presented. The tool then executes exactly the signed amount, currency, counterparty and details and nothing else.
2. Payment initiation. The payment service accepts an instruction from an agent only with a valid action envelope and its mandate. It verifies them with the details or detailsDigest of the instruction it is about to execute, the counterpartyKeyId or exact counterparty text of the payee it will pay and its own record of executed actions as executed, and gives its own executed actions under the mandate as priorActions. In strict mode, the default, an action with an amount stays indeterminate unless the details and the payee key are given, so funds are never released for a payee or details the agent did not sign. In the same step that releases funds, the service calls consume with the action and its own ledger folder or store, which records the reference of the action durably and refuses a reference already recorded, and then pays exactly the signed amount, currency, counterparty and details. Funds are never released when consume refuses or fails.
3. Platforms serving many clients. Each client signs mandates for the agents that act for it, so every client can see and prove the limits under which its agents operated.
4. Dispute handling. When a customer or counterparty disputes an action, the envelope, the mandate and the receipts show who authorised it and that it was within authority.
5. Audit and supervision. Auditors sample actions and verify each against its mandate and the running total of earlier actions.

## What is published and what stays private

Mandates, actions and revocations stay with the organisation and the parties it chooses to share them with. Action details such as invoices, payment instructions or customer data are represented only by a SHA3 fingerprint.

When an envelope is anchored, only a 32 byte Qstamp commitment reaches the chain. It is derived from a salted fingerprint of the signed statement and cannot be reversed into the mandate, the action, the amount, the counterparty or any other field.

## Cryptographic construction

1. Keys. Principal and agent keys are 32 byte seeds from which ML-DSA-65 key pairs are derived by the key generation procedure of FIPS 204. A key identifier is the SHA3 hash with a 256 bit output of the ASCII label quantova/qmandate/key/1, the byte 0x00 and the 1952 byte public key.

2. Statements. Each statement is a canonical binary encoding that begins with the ASCII bytes QMDT and a version byte, followed by the statement type and its fields in a fixed order. Every field is an unsigned 16 bit big endian length followed by its bytes, and lists are encoded as a count followed by their items, so every statement has exactly one encoding. A mandate uses the format qmandate/1 and the version byte 1, and encodes the mandate identifier, the principal and agent key identifiers, the agent label, each scope as action, currency, limit per action and total limit, the counterparties, the validity period, the issue time and a note. An action uses the format qmandate/3 and the version byte 3, and encodes the mandate identifier, the mandate reference, a fresh action identifier, the agent key identifier, the action, currency, amount, counterparty, the fingerprint of the details, the time, its number within its scope as decimal text starting at 1, the reference of the previous action of the scope, empty for the first, the running total including this action as decimal text, the 16 byte identifier of the spend ledger that signed it, and a note. Actions in the format qmandate/2 and the version byte 2 encode the same fields without the ledger identifier, are still read for verification and count as one ledger without an identifier. A revocation uses the format qmandate/1 and the version byte 1, and encodes the mandate identifier, the mandate reference, the principal key identifier, the time and a note. Actions in the older format qmandate/1 carry no number, previous reference or running total and are still read for verification.

3. Signatures. Statements are signed with ML-DSA-65 in its hedged form under the FIPS 204 context string quantova/qmandate/1. This context separates QMandate signatures from QSign signatures, from Quantova network transactions and from every other use of the algorithm.

4. Mandate reference. Every action names its mandate by the SHA3 hash of the label quantova/qmandate/ref/1, the byte 0x00, the encoded mandate and its signature. An action therefore relies on one exact signed mandate and cannot be moved to another. The reference of a previous action is computed in the same way from the encoded action and its signature, so the actions of a scope form a hash chain back to the first.

5. Anchor. To anchor an envelope, QMandate stamps the SHA3 hash of the label quantova/qmandate/anchor/1, the byte 0x00, the encoded statement and its signature, as a Qstamp record for mandates and revocations and as an AI agent action for actions.

## Rules applied by verification

1. The envelope is of the type the verifier expects, is well formed, and its signer identifier matches its public key.
2. A mandate is signed by the principal it names, and an action by the agent it names.
3. The action names the exact mandate by its reference, and the mandate names the agent that signed the action.
4. The action is listed in the mandate, in the permitted currency and within the limit per action.
5. The counterparty is permitted when the mandate lists counterparties.
6. The action falls within the period of validity, judged by its anchor time when it is anchored. A claimed time more than 24 hours before its anchor, a window the verifier may change, or an anchor made after a time of verification that is given, is reported as not proven.
7. When both are anchored, the mandate was recorded no later than the action.
8. No revocation signed by the principal was recorded at or before the action.
9. The running total the agent signed stays within the total limit. The earlier actions supplied must form an unbroken chain from this action back to action 1 of its scope, each naming the reference of the one before it, numbered one lower, with a running total equal to the total before it plus its own amount. A missing link leaves the result indeterminate and a broken link makes it invalid.
10. No two different actions of the same scope under the mandate carry the same number up to the number of this action. Two such actions show that the agent signed outside its ledger, so the result is invalid.
11. The agent did not reuse the identifier of this action for a different action.
12. When the private details are supplied, they match the fingerprint the agent signed.
13. When the verifier gives counterpartyKeyId, the action names the counterparty as the word key, a space and that key identifier.
14. In strict mode an action with an amount is valid only when the verifier gives the details or detailsDigest together with the payee, either as counterpartyKeyId for a payee named by its key or as counterparty, the exact payee text the tool will pay, so what a tool executes is bound to what the agent signed. Without them the result is indeterminate.
15. Every action supplied of the same scope under the mandate names the same ledger identifier, and no action in the format qmandate/2 follows an action that carries one. Two identifiers show that the agent signed from two ledgers, so the result is invalid. An action that names a previous action other than the one supplied at that number is a fork and is invalid.
16. When the verifier gives executed, a Set of references of actions already executed or a function that answers for a reference, an action already executed fails the check named once and is invalid. The result returns the reference of the action as actionRef.

An action in the format qmandate/1 is accepted only when the mandate was issued, or the action was anchored with a proven time, before LEGACY_CUTOFF, the moment on 17 October 2026 when the chained format was released, which the library exports. Under a mandate that holds actions in a newer format, an action in the format qmandate/1 anchored after the first of them is invalid, and one whose order against them is not proven is indeterminate. For an action in the older format qmandate/1 the running total is computed from the earlier actions supplied. Versions that signed this format anchored actions without the deadline of their mandate, so such an anchor is accepted with acceptLegacyActions and its proven time is still checked against the period of the mandate, and without it the result is indeterminate. Earlier actions are identified by their full signed content, every anchored copy is checked and the earliest proven time is used, and earlier actions recorded in the same block count unless their order within one anchoring transaction shows otherwise. Because these actions carry no number or signed total, nothing proves that every earlier action was supplied, so an action in the older format that carries an amount is reported indeterminate unless the verifier sets acceptLegacyActions, or passes --accept-legacy-actions, to accept that risk for actions signed before the newer format existed. When a mandate holds actions in both formats, action 1 of the newer format may start from an opening total, which must cover every older action supplied.

A result is valid only when the expected principal is given, the revocation list and the list of earlier actions are supplied, even if empty, and the mandate and the action are anchored with a proven time. When any of these is missing the result is indeterminate rather than valid, so a gap in the evidence can never be mistaken for proof. A verifier may accept unanchored envelopes explicitly when it needs to.

An anchor counts as proven only when Qstamp reports it proven, which needs at least two pinned independent operators of the network or a light client proof. An anchor confirmed by custom endpoints, or by a single endpoint under trustSingleEndpoint, is reported as unproven and the result is never valid. Verification and act run in strict mode by default. In strict mode an unproven anchor is treated as not anchored, so it can neither prove nor disprove an order of events, and trustSingleEndpoint is refused. With strict set to false the times of unproven anchors are used to order events and the result names them, but it is still never valid.

The agent label, the counterparties of a mandate and the counterparty of an action are text written by the principal and the agent. They are self asserted and are not verified identities, and the verifier says so in its notes. To bind a counterparty to a key identity, the principal lists it as the word key, a space and the 64 character key identifier of the counterparty, the agent names it the same way, and the verifier gives counterpartyKeyId, which the counterparty proves it holds to the payment provider.

A revocation or an earlier action that is not validly signed by the right key is ignored, so no third party can withdraw a mandate or distort a running total. A revocation applies to the mandate identifier, so it withdraws every signed copy of that mandate.

## Trust model of this release

This release anchors on the live Quantova network Q-test-net-1. The signing module is compiled from the Quantova Q-Crypto library, which follows FIPS 204 and FIPS 202 and has been tested against the NIST vectors and cross checked against an independent implementation. It has not been validated under FIPS 140-3. An anchor time is accepted only when Qstamp proves the anchor, either by a finality certificate checked against a pinned validator roster or by official endpoints of the network run by two different operators. An anchor confirmed by endpoints of one operator, or by endpoints chosen by the verifier, is reported as unproven and is never valid, whatever options are set. While the network has one official endpoint and no pinned roster every anchor is unproven, which is the honest result. Verification names the endpoints it consulted and says whether they are the official endpoints of the network.

A mandate proves the authority given by a principal key. Matching that key to an accountable person or function is a matter for the organisation, for example through a published key description and its internal approval records. A running total is proven complete only when every earlier action of the scope is supplied to the verifier. The ledger stops an honest agent from overspending under concurrency, and the signed number, total and ledger identifier make any overspending by an agent that signs outside its ledger visible as a fork or as a second ledger, but only to a verifier that is given actions from both. A payment provider that sees one action alone should ask for the earlier actions of its scope and add its own executed actions under the mandate. A verifier should use the earliest anchored copy of a mandate, because anyone can anchor a further copy later. Text fields accept only visible characters in Unicode normal form C, and amounts are whole numbers of minor units of at most thirty digits. A mandate may last at most ten years.

## Installation

```
npm install @quantovainc/qmandate
```

QMandate requires Node 20 or later.

## Command line use

```
qmandate keygen treasury.key
qmandate keygen agent.key
qmandate key agent.key > agent.pub.json

qmandate grant --key treasury.key --agent agent.pub.json --agent-label "Supplier payments agent" --scope payment.send,USD,500000,2000000 --counterparty "key $ACME_KEY_ID" --valid-until 2027-01-01T00:00:00.000Z --out mandate.json

qmandate check --mandate mandate.json --action payment.send --currency USD --amount 150000 --counterparty "key $ACME_KEY_ID" --ledger ledger

qmandate act --key agent.key --mandate mandate.json --ledger ledger --action payment.send --currency USD --amount 150000 --counterparty "key $ACME_KEY_ID" --details-file invoice.pdf --out action.json

qmandate anchor mandate.json --seed-file account.key
qmandate anchor action.json --seed-file account.key
qmandate complete action.json --pending action.json.pending.json

qmandate verify action.json --type action --mandate mandate.json --principal-public-key treasury.pub.json --details-file invoice.pdf --counterparty-key-id $ACME_KEY_ID --no-revocations --no-prior-actions

qmandate revoke --key treasury.key --mandate mandate.json --note "Agent retired" --out revoke.json
```

The check command gives the advice of authorise and never gates an action, which runs only once the act command has written its signed action. Verification requires the expected principal and either the revocations and earlier actions or the flags that state there are none. Unanchored envelopes are accepted only with the allow unanchored flag. The command exits with status 0 when the result is valid or the action is allowed, 1 when it is invalid, refused or cannot be read, 2 when it cannot be decided or rests on an unproven anchor, and 64 for usage errors. Key files must be readable only by their owner and are never followed through symbolic links.

## Programmatic use

```js
const qm = require('@quantovainc/qmandate');

const mandate = qm.grant({
  key: principalKey,
  agent: agentKeyDescription,
  scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '500000', maxTotal: '2000000' }],
  counterparties: ['key ' + acmeKeyId],
  validUntil: '2027-01-01T00:00:00.000Z',
});

const ledger = '/var/lib/agent/ledger';

const action = await qm.act({ key: agentKey, mandate, ledger, action: 'payment.send', currency: 'USD', amount: '150000', counterparty: 'key ' + acmeKeyId, details: invoiceBytes, revocations, rpc });

const result = await qm.verify(action, { type: 'action', mandate, principalKeyId, priorActions, revocations, details: invoiceBytes, counterpartyKeyId: acmeKeyId, executed: alreadyExecuted, rpc });

if (result.valid) {
  await qm.consume(action, '/var/lib/payments/executed');
  await sendPayment(action.statement);
}
```

The payment is sent only after act has returned the signed action, verify has bound it to the invoice and the payee key, and consume has recorded its reference. consume refuses a reference it has already recorded, so the same action never pays twice. When the mandate does not permit it, act throws an error with the code QMANDATE_NOT_AUTHORISED and the reasons, and nothing is sent. Options are read only from the object passed in, never from properties it inherits.

## Independent verification procedure

1. Decode each public key and signature from base64 and confirm their lengths are 1952 and 3309 bytes.
2. Compute each key identifier from the label quantova/qmandate/key/1, the byte 0x00 and the public key, and compare it with the signer identifier.
3. Encode each statement as described above and verify its signature with ML-DSA-65 under the context string quantova/qmandate/1, following FIPS 204.
4. Compute the mandate reference and confirm the action names it, and confirm the agent and principal identifiers match.
5. Apply the rules of verification listed above to the scope, limits, counterparty, period, revocations, the chain of earlier actions and the running total.
6. Compute the anchor value of each envelope and verify its receipt by the procedure published with Qstamp, and compare the anchor heights or times as the rules require.

## Network

The live Quantova network is named Q-test-net-1 with genesis hash ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062. Anchors are recorded by the official Qstamp contract on that network. The public endpoint is https://rpc-testnet.quantova.org. By default verification consults the official endpoints of the network. Endpoints chosen by the verifier are given with the rpc or clients option, or with --rpc once for each on the command line, and verification consults them only with trustCustomEndpoints, or --trust-custom-endpoints. An endpoint on a loopback address is refused unless allowLoopback, or --allow-loopback, is set, and an endpoint on a private network address unless it is named in endpointAllowList, or with --allow-endpoint. The option expectedSender, or --expect-sender, names the Quantova accounts entitled to anchor records, and an anchor signed by any other account is invalid. Anchoring accepts chain data only when at least two endpoints run by different operators agree, and the option trustSingleEndpoint, or --trust-single-endpoint, relies on one endpoint for anchoring and for the time of the chain. Decisions about expiry in act, authorise and verify use the time of the finalised chain head read from those endpoints and never the local clock alone, and act and authorise return promises. Agent actions are anchored through the stamp_until entry of the Qstamp contract with a deadline that is never later than the expiry of their mandate, so the chain refuses to anchor an action once the mandate has expired. Anchoring or completing actions therefore needs the mandate option, or --mandate on the command line.

The deadline is published on chain in clear. To avoid linking the actions of one mandate through it, QMandate does not publish the expiry itself. While the expiry is more than about two hours away, the deadline is the second full hour after the time of the chain, which depends only on when the batch is anchored and is shared by every batch anchored in that hour. Closer to the expiry, the deadline is the expiry rounded down to the hour, to ten minutes or to the minute, whichever still leaves five minutes to anchor, and only in the last five minutes is it the exact expiry. A verifier accepts any deadline at or before the expiry. Some linkage remains. Batches anchored in the last two hours of a mandate share a deadline derived from its expiry, every anchor shows the account that sent it and that it is an AI agent action, and anchors sent from one account can be linked to each other. Organisations that need actions of different mandates to be unlinkable should anchor them from different accounts.

## Licence

QMandate is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files LICENSE-APACHE and LICENSE-MIT, and the notice is in NOTICE.
