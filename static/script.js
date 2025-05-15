// Global variable to hold the results for download
let scanResultsData = null;

// DOM Elements
const urlInput = document.getElementById('urlInput');
const scanButton = document.getElementById('scanButton');
const loadingSpinner = document.getElementById('loadingSpinner');
const errorMessage = document.getElementById('errorMessage');
const errorText = document.getElementById('errorText');
const resultsSection = document.getElementById('resultsSection');
const scannedTarget = document.getElementById('scannedTarget');

// Result display elements
const metadataResultsEl = document.getElementById('metadataResults');
const dnsResultsEl = document.getElementById('dnsResults');
const whoisResultsEl = document.getElementById('whoisResults');
const subdomainsResultsEl = document.getElementById('subdomainsResults');
const smtpResultsEl = document.getElementById('smtpResults');
const blacklistResultsEl = document.getElementById('blacklistResults');


/**
 * Initiates the scan process when the scan button is clicked.
 */
async function startScan() {
    const urlValue = urlInput.value.trim();

    if (!urlValue) {
        showError('Please enter a URL or domain name.');
        return;
    }

    // Simplified regex: backend handles more robust validation
    const basicUrlOrDomainRegex = /^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n?]+)/i;
    if (!basicUrlOrDomainRegex.test(urlValue)) {
         showError('Invalid format. Please enter a valid URL or domain name.');
         return;
    }

    // UI Reset
    hideError();
    resultsSection.classList.add('d-none');
    loadingSpinner.classList.remove('d-none');
    scanButton.disabled = true;
    scanButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Scanning...';
    scanResultsData = null;

    try {
        // API Call
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ url: urlValue }),
        });
        const result = await response.json();

        if (!response.ok) {
            const errorMsg = result?.error || `Scan failed with status: ${response.status}. Please check the URL or server logs.`;
            throw new Error(errorMsg);
        }

        // Process Success
        scanResultsData = result;
        displayResults(scanResultsData);
        resultsSection.classList.remove('d-none');

    } catch (error) {
        console.error('Scan Error:', error);
        showError(error.message || 'An unexpected error occurred during the scan.');
        resultsSection.classList.add('d-none');

    } finally {
        // Cleanup UI
        loadingSpinner.classList.add('d-none');
        scanButton.disabled = false;
        scanButton.innerHTML = '<i class="bi bi-search me-2"></i>Scan';
    }
}

/**
 * Displays the scan results in the respective sections.
 * @param {object} results - The JSON object containing scan results from the backend.
 */
function displayResults(results) {
    scannedTarget.textContent = results.target_url || results.target_domain || 'N/A';

    metadataResultsEl.textContent = formatResult(results.metadata);
    dnsResultsEl.textContent = formatResult(results.dns_records);
    whoisResultsEl.textContent = formatResult(results.whois);
    subdomainsResultsEl.textContent = formatSubdomainResult(results.subdomains);
    smtpResultsEl.textContent = formatSmtpResult(results.smtp_diagnostics);
    blacklistResultsEl.textContent = formatBlacklistResult(results.blacklist_checks);

     const firstAccordionButton = document.querySelector('#scanResultsAccordion .accordion-button');
     const firstAccordionCollapse = document.querySelector('#scanResultsAccordion .accordion-collapse');
     if (firstAccordionButton && firstAccordionCollapse) {
         if (!firstAccordionCollapse.classList.contains('show')) {
            new bootstrap.Collapse(firstAccordionCollapse).show(); // Use Bootstrap's JS API
         }
         // Ensure all other sections start collapsed
         const otherCollapses = document.querySelectorAll('#scanResultsAccordion .accordion-item:not(:first-child) .accordion-collapse.show');
         otherCollapses.forEach(col => new bootstrap.Collapse(col).hide());
     }
}

/**
 * Formats general result data (object or array) into a readable string.
 */
function formatResult(data) {
    if (data === null || data === undefined) return 'No data received or not applicable.';
    if (typeof data === 'object' && data !== null) {
        if (data.hasOwnProperty('error')) return `Error: ${data.error}`;
        if (data.hasOwnProperty('warning')) return `Warning: ${data.warning}`;
        if (data.hasOwnProperty('info')) return `Info: ${data.info}`;
    }
    if (Array.isArray(data) && data.length === 0) return '[] (No items found or not applicable)';
    if (typeof data === 'object' || Array.isArray(data)) {
        try {
            return JSON.stringify(data, null, 2);
        } catch (e) {
            return "Error formatting data: Could not stringify object.";
        }
    }
    return String(data);
}

/**
 * Specifically formats the structured subdomain result object for display.
 */
function formatSubdomainResult(subData) {
    if (!subData || typeof subData !== 'object') return 'Invalid subdomain result data received.';
    if (subData.hasOwnProperty('error')) return `Error: ${subData.error}`;
    if (subData.hasOwnProperty('warning')) return `Warning: ${subData.warning}`;

    let output = `--- Subdomain Enumeration Summary ---\n`;
    output += `${subData.summary || 'No summary available.'}\n\n`;
    output += `--- Source Status ---\n`;
    if (subData.sources_status && typeof subData.sources_status === 'object') {
        for (const source in subData.sources_status) {
            output += `- ${source}: ${subData.sources_status[source]}\n`;
        }
    } else { output += "No source status available.\n"; }
    output += `\n--- Errors Encountered ---\n`;
    if (subData.errors && Array.isArray(subData.errors) && subData.errors.length > 0) {
        const actualErrors = subData.errors.filter(e => !e.toLowerCase().includes("no critical errors"));
        output += (actualErrors.length > 0 ? actualErrors.join('\n') : subData.errors[0]) + '\n';
    } else { output += "No errors reported.\n"; }
    output += `\n--- Discovered Subdomains ---\n`;
    if (subData.subdomains && Array.isArray(subData.subdomains) && subData.subdomains.length > 0) {
        const actualSubdomains = subData.subdomains.filter(s => !s.toLowerCase().includes("no subdomains found"));
        if (actualSubdomains.length === 0 && subData.subdomains.length > 0) { // Case: only "no subdomains" messages
            output += subData.subdomains[0] + '\n';
        } else if (actualSubdomains.length > 0) {
            output += actualSubdomains.join('\n') + '\n';
        } else {
             output += "No subdomains listed or found by enabled methods.\n";
        }
    } else { output += "No subdomains list available or list is empty.\n"; }
    return output;
}

/**
 * Formats the SMTP diagnostics result object for display.
 */
function formatSmtpResult(smtpData) {
    if (!smtpData || typeof smtpData !== 'object') return 'Invalid SMTP result data received.';
    if (smtpData.hasOwnProperty('error')) return `Error: ${smtpData.error}`;
    if (smtpData.hasOwnProperty('warning')) return `Warning: ${smtpData.warning}`;
    if (smtpData.hasOwnProperty('info')) return `Info: ${smtpData.info}`;

    let output = "--- SMTP Server Checks ---\n";
    if (Object.keys(smtpData).length === 0) {
        return output + "No SMTP servers checked (likely no MX records found or parsed).";
    }

    for (const serverName in smtpData) {
        const result = smtpData[serverName];
        output += `\n[Server: ${serverName}]\n`;
        output += `  Status: ${result.status || 'N/A'}\n`;
        if (result.connect_time_ms !== null && result.connect_time_ms !== undefined) {
            output += `  Connect Time: ${result.connect_time_ms} ms\n`;
        }
        output += `  Banner: ${result.banner || 'Not captured'}\n`;
        output += `  Errors:\n`;
        if (result.errors && Array.isArray(result.errors) && result.errors.length > 0) {
             const actualErrors = result.errors.filter(e => !e.toLowerCase().includes("no errors encountered"));
             if (actualErrors.length > 0) {
                 output += actualErrors.map(e => `    - ${e}`).join('\n') + '\n';
             } else if (result.errors.length > 0) { // Show "no errors encountered" if it's the only message
                 output += `    - ${result.errors[0]}\n`;
             } else { // Should not happen if array has items but filter is empty and length > 0 fails
                output += "    - No specific errors recorded.\n";
             }
        } else {
            output += "    - No specific errors recorded.\n";
        }
    }
    return output;
}

/**
 * Formats the Blacklist check result object for display.
 */
function formatBlacklistResult(blData) {
    if (!blData || typeof blData !== 'object') return 'Invalid Blacklist result data received.';
    if (blData.hasOwnProperty('error')) return `Error: ${blData.error}`;
    if (blData.hasOwnProperty('warning')) return `Warning: ${blData.warning}`;
    if (blData.hasOwnProperty('info')) return `Info: ${blData.info}`;

    let output = "--- Blacklist Check (DNSBL) ---\n";

    output += "\n--- Summary ---\n";
    if (blData.summary && typeof blData.summary === 'object') {
        output += `IPs Checked: ${blData.summary.ips_checked || 0}\n`;
        output += `Blacklists Queried: ${blData.summary.blacklists_queried || 0}\n`;
        output += `Listings Found: ${blData.summary.listings_found || 0}\n`;
        output += `Timeouts During Check: ${blData.summary.timeouts || 0}\n`;
        output += `Errors During Check: ${blData.summary.errors || 0}\n`;
    } else {
        output += "No summary available.\n";
    }

    output += "\n--- Details per IP ---\n";
    if (blData.details && typeof blData.details === 'object' && Object.keys(blData.details).length > 0) {
        for (const ip in blData.details) {
            output += `\n[IP: ${ip}]\n`;
            let listedOn = [];
            let errored = [];
            let timeouts = [];
            let notListedCount = 0;
            let checkedCount = 0;

            if (blData.details[ip] && typeof blData.details[ip] === 'object') {
                checkedCount = Object.keys(blData.details[ip]).length;
                for (const dnsbl in blData.details[ip]) {
                    const result = blData.details[ip][dnsbl];
                    if (result === true) {
                        listedOn.push(dnsbl);
                    } else if (result === "Timeout") {
                         timeouts.push(dnsbl);
                    } else if (result === false) {
                        notListedCount++;
                    } else {
                        errored.push(`${dnsbl} (${result})`);
                    }
                }
            }

            if (listedOn.length > 0) {
                 output += `  LISTED on: ${listedOn.join(', ')}\n`;
            } else if (checkedCount > 0 && timeouts.length < checkedCount && errored.length < checkedCount){
                 output += `  Not found on any queried blacklist where check succeeded.\n`;
            } else if (checkedCount === 0) {
                output += `  No blacklist checks performed or reported for this IP.\n`;
            }


             if (timeouts.length > 0) {
                 output += `  Timeouts on: ${timeouts.join(', ')}\n`;
            }
             if (errored.length > 0) {
                 output += `  Errors on: ${errored.join(', ')}\n`;
            }
            if (checkedCount > 0) {
                 output += `  (Checked ${checkedCount} lists for this IP: ${notListedCount} clean, ${listedOn.length} listed, ${timeouts.length} timeouts, ${errored.length} errors)\n`;
            }
        }
    } else {
        output += "No detailed IP results available (or no IPs were checked).\n";
    }

    return output;
}


/**
 * Displays an error message in the designated error area.
 */
function showError(message) {
    errorText.textContent = message;
    errorMessage.classList.remove('d-none');
}

/**
 * Hides the error message area.
 */
function hideError() {
    errorMessage.classList.add('d-none');
    errorText.textContent = '';
}

/**
 * Triggers the download of the stored scan results as a JSON file.
 */
function downloadResults() {
    if (!scanResultsData) {
        showError('No scan results available to download.');
        return;
    }
    try {
        const jsonData = JSON.stringify(scanResultsData, null, 2);
        const blob = new Blob([jsonData], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        const filenameBase = (scanResultsData.target_domain || scanResultsData.target_url || 'scan_results').replace(/^(https?:\/\/)/, '').replace(/[\/\?#:"<>|*]/g, '_');
        const filename = `${filenameBase}_scan_results.json`;
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Download Error:', error);
        showError('Failed to generate download file.');
    }
}

// --- Event Listeners ---
if (urlInput) {
    urlInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            if (!scanButton.disabled) startScan();
        }
    });
    urlInput.addEventListener('input', hideError);
}

if (scanButton) {
    // The onclick attribute is already set in HTML, but if you prefer JS-only:
    // scanButton.addEventListener('click', startScan);
}

// Smooth scrolling for navbar links
document.querySelectorAll('nav a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const targetId = this.getAttribute('href');
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
            targetElement.scrollIntoView({
                behavior: 'smooth'
            });
        }
    });
});