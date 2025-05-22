(() => {
  'use strict';

  const fileInput = document.getElementById('fileInput');
  const passwordInput = document.getElementById('passwordInput');
  const encryptBtn = document.getElementById('encryptBtn');
  const decryptBtn = document.getElementById('decryptBtn');
  const status = document.getElementById('status');
  const progressBar = document.getElementById('progress-bar');
  const lockOverlay = document.getElementById('lock-overlay');

  const SESSION_TIMEOUT_MS = 5 * 60 * 1000;
  let sessionTimer;

  let fileData = null;
  let fileName = '';
  let isEncryptedFile = false;

  function updateButtons() {
    const hasFile = fileData !== null;
    const hasPass = passwordInput.value.length >= 6;

    encryptBtn.disabled = !(hasFile && hasPass);
    decryptBtn.disabled = !(hasFile && hasPass && isEncryptedFile);
  }

  function resetStatus() {
    status.textContent = '';
    progressBar.style.width = '0%';
  }

  function readFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = () => reject('File reading error');
      reader.readAsArrayBuffer(file);
    });
  }

  function getRandomBytes(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
  }

  function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for(let i=0; i<len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for(let i=0; i<len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      {name: 'PBKDF2'},
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 250000,
        hash: 'SHA-256'
      },
      passKey,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function sha256(buffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return new Uint8Array(hashBuffer);
  }

  function compressData(buffer) {
    const uint8Arr = new Uint8Array(buffer);
    let str = '';
    for(let i=0; i<uint8Arr.length; i++) {
      str += String.fromCharCode(uint8Arr[i]);
    }
    return LZString.compressToBase64(str);
  }

  function decompressData(compressed) {
    const decompressedStr = LZString.decompressFromBase64(compressed);
    if (!decompressedStr) throw new Error('Decompression failed');
    const buffer = new Uint8Array(decompressedStr.length);
    for(let i=0; i<decompressedStr.length; i++) {
      buffer[i] = decompressedStr.charCodeAt(i);
    }
    return buffer.buffer;
  }

  async function encryptFile(buffer, password) {
    resetStatus();
    progressBar.style.width = '10%';

    const salt = getRandomBytes(16);
    const iv = getRandomBytes(16);

    progressBar.style.width = '20%';

    const key = await deriveKey(password, salt);

    progressBar.style.width = '40%';

    const compressed = compressData(buffer);
    const compressedBuffer = new TextEncoder().encode(compressed);

    progressBar.style.width = '60%';

    const encryptedBuffer = await crypto.subtle.encrypt(
      {name: 'AES-CBC', iv: iv},
      key,
      compressedBuffer
    );

    progressBar.style.width = '80%';

    const hash = await sha256(compressedBuffer);

    progressBar.style.width = '90%';

    const resultObj = {
      iv: arrayBufferToBase64(iv.buffer),
      salt: arrayBufferToBase64(salt.buffer),
      hash: arrayBufferToBase64(hash.buffer),
      data: arrayBufferToBase64(encryptedBuffer)
    };

    progressBar.style.width = '100%';

    return new Blob([JSON.stringify(resultObj)], {type: 'application/json'});
  }

  async function decryptFile(encryptedText, password) {
    resetStatus();
    progressBar.style.width = '10%';

    const obj = JSON.parse(encryptedText);

    const iv = base64ToArrayBuffer(obj.iv);
    const salt = base64ToArrayBuffer(obj.salt);
    const hashStored = base64ToArrayBuffer(obj.hash);
    const encryptedData = base64ToArrayBuffer(obj.data);

    progressBar.style.width = '30%';

    const key = await deriveKey(password, salt);

    progressBar.style.width = '50%';

    let decryptedBuffer;
    try {
      decryptedBuffer = await crypto.subtle.decrypt(
        {name: 'AES-CBC', iv: new Uint8Array(iv)},
        key,
        encryptedData
      );
    } catch {
      throw new Error('Decryption failed: Wrong password or corrupted file.');
    }

    progressBar.style.width = '70%';

    // Verify hash
    const hashCalc = await sha256(decryptedBuffer);
    if (hashCalc.length !== hashStored.byteLength) throw new Error('Hash length mismatch');
    for(let i=0; i<hashCalc.length; i++) {
      if (hashCalc[i] !== new Uint8Array(hashStored)[i]) throw new Error('Data integrity check failed');
    }

    progressBar.style.width = '90%';

    const decompressedBuffer = decompressData(new TextDecoder().decode(decryptedBuffer));

    progressBar.style.width = '100%';

    return decompressedBuffer;
  }

  function downloadFile(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  fileInput.addEventListener('change', async () => {
    resetStatus();
    const file = fileInput.files[0];
    if (!file) {
      fileData = null;
      fileName = '';
      isEncryptedFile = false;
      updateButtons();
      return;
    }
    fileName = file.name;

    try {
      const buffer = await readFile(file);

      // Check if encrypted JSON file (for decrypt button toggle)
      const text = new TextDecoder().decode(buffer);
      isEncryptedFile = false;
      try {
        const obj = JSON.parse(text);
        if (obj && obj.iv && obj.salt && obj.hash && obj.data) {
          isEncryptedFile = true;
        }
      } catch {}

      fileData = buffer;
      status.textContent = `File loaded: ${fileName} (${(buffer.byteLength/1024).toFixed(2)} KB)`;
      updateButtons();
    } catch (e) {
      fileData = null;
      fileName = '';
      isEncryptedFile = false;
      status.textContent = 'Error loading file';
      updateButtons();
    }
  });

  passwordInput.addEventListener('input', updateButtons);

  encryptBtn.addEventListener('click', async () => {
    if (!fileData || passwordInput.value.length < 6) return;

    try {
      status.textContent = 'Encrypting... Please wait.';
      const encryptedBlob = await encryptFile(fileData, passwordInput.value);
      downloadFile(encryptedBlob, fileName + '.enc.json');
      status.textContent = `Encryption complete. File saved as ${fileName}.enc.json`;
      progressBar.style.width = '0%';
    } catch (e) {
      status.textContent = 'Encryption error: ' + e.message;
      progressBar.style.width = '0%';
    }
  });

  decryptBtn.addEventListener('click', async () => {
    if (!fileData || passwordInput.value.length < 6) return;

    try {
      status.textContent = 'Decrypting... Please wait.';
      const text = new TextDecoder().decode(fileData);
      const decryptedBuffer = await decryptFile(text, passwordInput.value);

      const originalFilename = fileName.replace(/\.enc\.json$/i, '') || 'decrypted_file';
      const decryptedBlob = new Blob([decryptedBuffer]);
      downloadFile(decryptedBlob, originalFilename);
      status.textContent = `Decryption complete. File saved as ${originalFilename}`;
      progressBar.style.width = '0%';
    } catch (e) {
      status.textContent = 'Decryption error: ' + e.message;
      progressBar.style.width = '0%';
    }
  });

  function startSessionTimer() {
    clearTimeout(sessionTimer);
    sessionTimer = setTimeout(() => {
      lockOverlay.style.display = 'flex';
      fileInput.disabled = true;
      passwordInput.disabled = true;
      encryptBtn.disabled = true;
      decryptBtn.disabled = true;
    }, SESSION_TIMEOUT_MS);
  }

  document.body.addEventListener('mousemove', startSessionTimer);
  document.body.addEventListener('keydown', startSessionTimer);
  document.body.addEventListener('click', startSessionTimer);

  startSessionTimer();

})();
