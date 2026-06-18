# Object Parser

Paste hex-encoded serialized data into the text area, select the object type, and click **Parse** to decode it into a
structured tree view.

<div id="wasm-parser" class="sample-root" markdown>

<textarea id="hex-input" placeholder="Paste hex-encoded raw bytes..." spellcheck="false" rows="4"></textarea>

<div class="parser-actions">
  <select id="type-select">
    <option value="block">Block</option>
    <option value="transaction">Transaction</option>
  </select>
  <button id="parse-btn" class="btn-primary" disabled>Parse</button>
  <button id="clear-btn">Clear</button>
</div>
<div id="error-msg" class="sample-error"></div>
<div id="warnings"></div>
<div id="output"></div>

</div>

<link rel="stylesheet" href="../common.css">
<link rel="stylesheet" href="style.css">
<script type="module" src="index.js"></script>
