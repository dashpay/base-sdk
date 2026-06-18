# Genesis Solver

Verify a genesis block in the browser by computing the proof-of-work within the browser. Select a network to load its
genesis parameters, then click **Solve** to check whether the nonce satisfies the difficulty target. If it does not,
nonces are scanned until a valid one is found. Change the values to compute your own.

<div id="wasm-genesis" class="sample-root">

<div class="genesis-toolbar">
  <select id="gen-network">
    <option value="mainnet">Mainnet</option>
    <option value="testnet">Testnet</option>
  </select>
  <button id="gen-reset">Reset</button>
  <span class="spacer"></span>
  <span id="gen-solve-info"></span>
  <button id="gen-solve" class="btn-primary">Solve</button>
</div>

<div class="genesis-section">
  <div class="genesis-section-title">Coinbase</div>
  <div id="gen-coinbase-error" class="genesis-adm genesis-danger hidden"></div>
  <div id="gen-version-warn" class="genesis-adm genesis-warn hidden">Version is not 1. The genesis block uses version 1.</div>
  <div class="genesis-field">
    <label for="gen-amount">Amount</label>
    <div class="field-with-toggle">
      <input id="gen-amount" type="text" spellcheck="false">
      <button id="gen-amount-toggle" class="toggle-btn">duffs</button>
    </div>
  </div>
  <div class="genesis-field">
    <label for="gen-scriptsig">Signature script</label>
    <div class="field-with-toggle">
      <textarea id="gen-scriptsig" rows="2" spellcheck="false"></textarea>
      <button id="gen-sig-toggle" class="toggle-btn">hex</button>
    </div>
  </div>
  <div class="genesis-field">
    <label for="gen-scriptpubkey">Output script</label>
    <textarea id="gen-scriptpubkey" rows="2" spellcheck="false"></textarea>
  </div>
</div>

<div class="genesis-section">
  <div class="genesis-section-title">Block header</div>
  <div id="gen-header-error" class="genesis-adm genesis-danger hidden"></div>
  <div class="genesis-row">
    <div class="genesis-field">
      <label for="gen-time">Timestamp</label>
      <input id="gen-time" type="text" spellcheck="false">
    </div>
    <div class="genesis-field">
      <label for="gen-bits">Difficulty</label>
      <div class="field-with-toggle">
        <input id="gen-bits" type="text" spellcheck="false">
        <button id="gen-bits-toggle" class="toggle-btn">hex</button>
      </div>
    </div>
  </div>
  <div class="genesis-row">
    <div class="genesis-field">
      <label for="gen-version">Version</label>
      <input id="gen-version" type="text" spellcheck="false">
    </div>
    <div class="genesis-field">
      <label for="gen-nonce">Nonce</label>
      <input id="gen-nonce" type="text" spellcheck="false">
    </div>
  </div>
</div>

<div class="genesis-section">
  <div class="genesis-section-title">Result</div>
  <div id="gen-match-note" class="genesis-adm genesis-note hidden">Matches the hardcoded Dash Core genesis hash for
    this network.</div>
  <div class="genesis-field">
    <label for="gen-merkle">Merkle root</label>
    <input id="gen-merkle" type="text" readonly>
  </div>
  <div class="genesis-field">
    <label for="gen-hash">Genesis hash</label>
    <input id="gen-hash" type="text" readonly>
  </div>
</div>

</div>

<link rel="stylesheet" href="../common.css">
<link rel="stylesheet" href="style.css">
<script type="module" src="index.js"></script>
