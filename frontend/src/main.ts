import { generateECDSAKeyPair, createCSR, createP12Bundle, dummyCASign, KeyPair } from './vending';

let currentUsername = 'Guest';
let localKeyPair: KeyPair | null = null;
let signedCertPem: string | null = null;
let rootCaPem: string | null = null;

function showContent(id: 'ready' | 'processing' | 'password' | 'success' | 'error') {
  ['ready', 'processing', 'password', 'success', 'error'].forEach(s => {
    document.getElementById('content-' + s)?.classList.add('hidden');
  });
  document.getElementById('content-' + id)?.classList.remove('hidden');
}

function updateStepper(step: number) {
  for (let i = 1; i <= 3; i++) {
    const nav = document.getElementById(`step-${i}-nav`);
    const circle = nav?.querySelector('div');
    if (circle) {
      if (i < step) {
        circle.classList.remove('bg-slate-200', 'bg-blue-600', 'text-white');
        circle.classList.add('bg-green-500', 'text-white');
        circle.innerHTML = '✓';
      } else if (i === step) {
        circle.classList.remove('bg-slate-200', 'bg-green-500', 'text-white');
        circle.classList.add('bg-blue-600', 'text-white');
        circle.innerHTML = i.toString();
      } else {
        circle.classList.remove('bg-blue-600', 'bg-green-500', 'text-white');
        circle.classList.add('bg-slate-200');
        circle.innerHTML = i.toString();
      }
    }
  }
}

async function startVending() {
  try {
    showContent('processing');
    updateStepper(1);

    const statusEl = document.getElementById('processing-status');
    
    // 1. Key Generation
    if (statusEl) statusEl.innerText = 'Generating ECDSA P-256 Keypair...';
    await new Promise(r => setTimeout(r, 100));

    localKeyPair = await generateECDSAKeyPair();

    // 2. CSR Creation
    updateStepper(2);
    if (statusEl) statusEl.innerText = 'Creating PKCS#10 CSR...';
    const csrPem = await createCSR(localKeyPair, currentUsername);

    // 3. Submitting to Signer (Simulated or Real)
    if (statusEl) statusEl.innerText = 'Signing with CA...';
    
    try {
      // Attempt real backend first
      const response = await fetch('/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csr: csrPem })
      });

      if (response.ok) {
        const data = await response.json();
        signedCertPem = data.cert;
        rootCaPem = data.root_ca;
      } else {
        console.warn('Backend signing failed, falling back to dummy CA for testing.');
        signedCertPem = dummyCASign(csrPem);
      }
    } catch (e) {
      console.warn('Backend unreachable, falling back to dummy CA for testing.', e);
      signedCertPem = dummyCASign(csrPem);
    }

    // 4. Prompt for Password
    updateStepper(3);
    showContent('password');

  } catch (err: any) {
    console.error(err);
    const errorEl = document.getElementById('error-message');
    if (errorEl) errorEl.innerText = err.message;
    showContent('error');
  }
}

async function finalizeBundle() {
  const passwordEl = document.getElementById('p12-password') as HTMLInputElement;
  const password = passwordEl?.value;
  if (!password) {
    alert('Please enter a transport password.');
    return;
  }

  if (!localKeyPair || !signedCertPem) {
      alert('Missing keypair or certificate. Please restart.');
      return;
  }

  try {
    showContent('processing');
    const statusEl = document.getElementById('processing-status');
    if (statusEl) statusEl.innerText = 'Creating PKCS#12 Bundle...';

    const certChain = [signedCertPem];
    if (rootCaPem) {
      certChain.push(rootCaPem);
    }

    const p12Buffer = await createP12Bundle(localKeyPair, certChain, password, currentUsername);
    
    // Trigger download
    downloadBlob(p12Buffer, `${currentUsername}.p12`, 'application/x-pkcs12');
    
    showContent('success');
  } catch (err: any) {
    console.error(err);
    const errorEl = document.getElementById('error-message');
    if (errorEl) errorEl.innerText = 'Failed to create P12 bundle: ' + err.message;
    showContent('error');
  }
}

function downloadBlob(data: ArrayBuffer, filename: string, mimeType: string) {
  const blob = new Blob([data], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  window.URL.revokeObjectURL(url);
}

async function init() {
  try {
    const resp = await fetch('/api/me');
    if (resp.ok) {
      const data = await resp.json();
      currentUsername = data.username;
    }
  } catch (e) {
    console.warn('Failed to fetch username, using Guest', e);
    currentUsername = 'Guest';
  }

  // Init UI
  const displayUsernameEl = document.getElementById('display-username');
  if (displayUsernameEl) displayUsernameEl.innerText = currentUsername;

  // Event Listeners
  document.getElementById('btn-start')?.addEventListener('click', startVending);
  document.getElementById('btn-finalize')?.addEventListener('click', () => {
    finalizeBundle().catch(console.error);
  });
}

init();
