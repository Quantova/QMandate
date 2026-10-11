# QMandate

QMandate is a post quantum authority layer for superintelligence agents. It proves which person or organisation authorised an agent, exactly what the agent was permitted to do, within which limits and for how long, and that every action the agent took stayed inside that authority. Every mandate and every action is signed with the Module Lattice Digital Signature Algorithm, parameter set 65, as standardised in FIPS 204, and each can carry a Qstamp time proof recorded on the Quantova chain.

## What QMandate is

An SI agent that pays suppliers, approves refunds, moves funds or answers customers acts on behalf of an organisation. When something goes wrong, three questions decide liability. Who authorised the agent. What exactly was it permitted to do. And did this action fall inside that permission at the moment it happened.

QMandate answers all three with cryptographic evidence. A principal, such as a treasury officer, a business unit or the organisation itself, signs a mandate that names one agent key and lists the permitted actions, the currency and limit of each, the counterparties the agent may deal with and the period the mandate is in force. The agent signs every action it takes, and each action names the exact mandate it relies on. A verifier, whether an auditor, a regulator, a payment provider or a court, can then confirm that the action was taken by that agent, under that mandate, within its limits and before any revocation, without trusting the agent, the organisation or Quantova Inc.

QMandate is standalone. It runs on the systems of the organisation, holds its keys locally, needs no blockchain wallet and no digital asset, and uses the Quantova chain only as a neutral public ledger for time proofs.

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

3. Grant a mandate. The principal signs a mandate naming the agent key, each permitted action with its currency, its limit per action and its total limit, the permitted counterparties if any, and the period of validity. Amounts are whole numbers of minor units, so 150000 in US dollars means 1,500.00 dollars. The mandate is anchored on the Quantova chain before the agent first uses it, which proves that the authority existed before any action taken under it.

4. Check before acting. Before the agent executes an action, the application calls authorise with the mandate, the intended action, the amount already spent under the mandate and any revocations it holds. The call returns allowed or refused with the reasons, entirely offline and in microseconds. An action that is refused is never executed.

5. Sign every action. When the agent executes, it signs an action statement with the action, the amount, the currency, the counterparty and a fingerprint of the private details such as an invoice or a payment instruction. The details themselves never leave the organisation. The application states the amount already spent, and QMandate refuses to sign an action that the mandate does not permit or that a supplied revocation has withdrawn.

6. Anchor on a schedule. A single service with a funded Quantova account anchors new actions in batches. Each action receives its own receipt.

7. Revoke when circumstances change. When an agent is retired, compromised or no longer needed, the principal signs and anchors a revocation. Every action recorded after it is shown to be invalid, and actions recorded before it remain valid.

8. Verify when evidence is needed. The organisation hands the action, the mandate, any revocations and the earlier actions under the same mandate to the party that asks. That party verifies them against the principal key it expects, with the verify command, the library or the independent procedure below. Verification always requires the expected principal, so a mandate issued by any other key is rejected.

## Integration patterns

1. Agent frameworks. A tool wrapper calls authorise before any tool that moves money or makes a commitment, and calls act after it succeeds.
2. Payment initiation. The payment service accepts an instruction from an agent only with a valid action envelope and its mandate, and checks them before releasing funds.
3. Platforms serving many clients. Each client signs mandates for the agents that act for it, so every client can see and prove the limits under which its agents operated.
4. Dispute handling. When a customer or counterparty disputes an action, the envelope, the mandate and the receipts show who authorised it and that it was within authority.
5. Audit and supervision. Auditors sample actions and verify each against its mandate and the running total of earlier actions.

## What is published and what stays private

Mandates, actions and revocations stay with the organisation and the parties it chooses to share them with. Action details such as invoices, payment instructions or customer data are represented only by a SHA3 fingerprint.

When an envelope is anchored, only a 32 byte Qstamp commitment reaches the chain. It is derived from a salted fingerprint of the signed statement and cannot be reversed into the mandate, the action, the amount, the counterparty or any other field.

## Cryptographic construction

1. Keys. Principal and agent keys are 32 byte seeds from which ML-DSA-65 key pairs are derived by the key generation procedure of FIPS 204. A key identifier is the SHA3 hash with a 256 bit output of the ASCII label quantova/qmandate/key/1, the byte 0x00 and the 1952 byte public key.

2. Statements. Each statement is a canonical binary encoding that begins with the ASCII bytes QMDT and the version byte 1, followed by the statement type and its fields in a fixed order. Every field is an unsigned 16 bit big endian length followed by its bytes, and lists are encoded as a count followed by their items, so every statement has exactly one encoding. A mandate encodes the mandate identifier, the principal and agent key identifiers, the agent label, each scope as action, currency, limit per action and total limit, the counterparties, the validity period, the issue time and a note. An action encodes the mandate identifier, the mandate reference, a fresh action identifier, the agent key identifier, the action, currency, amount, counterparty, the fingerprint of the details, the time and a note. A revocation encodes the mandate identifier, the mandate reference, the principal key identifier, the time and a note.

3. Signatures. Statements are signed with ML-DSA-65 in its hedged form under the FIPS 204 context string quantova/qmandate/1. This context separates QMandate signatures from QSign signatures, from Quantova chain transactions and from every other use of the algorithm.

4. Mandate reference. Every action names its mandate by the SHA3 hash of the label quantova/qmandate/ref/1, the byte 0x00, the encoded mandate and its signature. An action therefore relies on one exact signed mandate and cannot be moved to another.

5. Anchor. To anchor an envelope, QMandate stamps the SHA3 hash of the label quantova/qmandate/anchor/1, the byte 0x00, the encoded statement and its signature, as a Qstamp record for mandates and revocations and as an SI agent action for actions.

## Rules applied by verification

1. The envelope is well formed and its signer identifier matches its public key.
2. A mandate is signed by the principal it names, and an action by the agent it names.
3. The action names the exact mandate by its reference, and the mandate names the agent that signed the action.
4. The action is listed in the mandate, in the permitted currency and within the limit per action.
5. The counterparty is permitted when the mandate lists counterparties.
6. The action falls within the period of validity, judged by its anchor time when it is anchored.
7. When both are anchored, the mandate was recorded no later than the action.
8. No revocation signed by the principal was recorded at or before the action.
9. The running total including this action stays within the total limit. Earlier actions are identified by their full signed content, every anchored copy is checked and the earliest proven time is used, and earlier actions recorded in the same block count unless their order within one anchoring transaction shows otherwise, so a batch of actions cannot exceed the limit together.
10. The agent did not reuse the identifier of this action for a different action.
11. When the private details are supplied, they match the fingerprint the agent signed.

A result is valid only when the expected principal is given, the revocation list and the list of earlier actions are supplied, even if empty, and the mandate and the action are anchored. When any of these is missing the result is indeterminate rather than valid, so a gap in the evidence can never be mistaken for proof. A verifier may accept unanchored envelopes explicitly when it needs to.

A revocation or an earlier action that is not validly signed by the right key is ignored, so no third party can withdraw a mandate or distort a running total. A revocation applies to the mandate identifier, so it withdraws every signed copy of that mandate.

## Trust model of this release

This release targets the Quantova test network. Anchors on that network carry no evidential weight. The signing module is compiled from the Quantova Q-Crypto library, which follows FIPS 204 and FIPS 202 and has been tested against the NIST vectors and cross checked against an independent implementation, but has not yet been independently audited or validated under FIPS 140-3.

A mandate proves the authority given by a principal key. Matching that key to an accountable person or function is a matter for the organisation, for example through a published key description and its internal approval records. Running totals are complete only when every earlier action under the mandate is supplied to the verifier. A verifier should use the earliest anchored copy of a mandate, because anyone can anchor a further copy later. Text fields accept only visible characters in Unicode normal form C, and amounts are whole numbers of minor units of at most thirty digits. A mandate may last at most ten years.

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

qmandate grant --key treasury.key --agent agent.pub.json --agent-label "Supplier payments agent" --scope payment.send,USD,500000,2000000 --counterparty "ACME Supplies Ltd" --valid-until 2027-01-01T00:00:00.000Z --out mandate.json

qmandate check --mandate mandate.json --action payment.send --currency USD --amount 150000 --counterparty "ACME Supplies Ltd" --spent 0

qmandate act --key agent.key --mandate mandate.json --action payment.send --currency USD --amount 150000 --counterparty "ACME Supplies Ltd" --details-file invoice.pdf --spent 0 --out action.json

qmandate anchor mandate.json --seed-file account.key
qmandate anchor action.json --seed-file account.key

qmandate verify action.json --mandate mandate.json --principal-public-key treasury.pub.json --details-file invoice.pdf --no-revocations --no-prior-actions

qmandate revoke --key treasury.key --mandate mandate.json --note "Agent retired" --out revoke.json
```

Verification requires the expected principal and either the revocations and earlier actions or the flags that state there are none. Unanchored envelopes are accepted only with the allow unanchored flag. The command exits with status 0 when the result is valid or the action is allowed, 1 when it is invalid, refused or cannot be read, 2 when it cannot be decided, and 64 for usage errors. Key files must be readable only by their owner and are never followed through symbolic links.

## Programmatic use

```js
const qm = require('@quantovainc/qmandate');

const mandate = qm.grant({
  key: principalKey,
  agent: agentKeyDescription,
  scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '500000', maxTotal: '2000000' }],
  counterparties: ['ACME Supplies Ltd'],
  validUntil: '2027-01-01T00:00:00.000Z',
});

const decision = qm.authorise(mandate, { action: 'payment.send', currency: 'USD', amount: '150000', counterparty: 'ACME Supplies Ltd' }, { spent: '0', revocations });

if (decision.allowed) {
  const action = qm.act({ key: agentKey, mandate, action: 'payment.send', currency: 'USD', amount: '150000', counterparty: 'ACME Supplies Ltd', details: invoiceBytes, spent: '0', revocations });
}

const result = await qm.verify(action, { mandate, principalKeyId, priorActions, revocations });
```

## Independent verification procedure

1. Decode each public key and signature from base64 and confirm their lengths are 1952 and 3309 bytes.
2. Compute each key identifier from the label quantova/qmandate/key/1, the byte 0x00 and the public key, and compare it with the signer identifier.
3. Encode each statement as described above and verify its signature with ML-DSA-65 under the context string quantova/qmandate/1, following FIPS 204.
4. Compute the mandate reference and confirm the action names it, and confirm the agent and principal identifiers match.
5. Apply the rules of verification listed above to the scope, limits, counterparty, period, revocations and running total.
6. Compute the anchor value of each envelope and verify its receipt by the procedure published with Qstamp, and compare the anchor heights or times as the rules require.

## Network

The Quantova test network is named Q-test-net-1 with genesis hash ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062. Anchors are recorded by the official Qstamp contract on that network. The public endpoint is https://rpc-testnet.quantova.org.

## Licence

QMandate is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files LICENSE-APACHE and LICENSE-MIT, and the notice is in NOTICE.
