// ==========================================
// PHISHGUARD - SCRIPT.JS (PART 1)
// Variables, Scanner Logic & Dashboard
// ==========================================

// ---------- ELEMENTS ----------

const scanBtn = document.getElementById("scanBtn");
const scanType = document.getElementById("scanType");
const targetInput = document.getElementById("targetInput");
const fileInput = document.getElementById("fileInput");

const loading = document.getElementById("loading");

const resultSection = document.getElementById("resultSection");
const riskBar = document.getElementById("riskBar");
const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");
const threatType = document.getElementById("threatType");
const status = document.getElementById("status");
const recommendation = document.getElementById("recommendation");
const scanTarget = document.getElementById("scanTarget");

const engineContainer = document.getElementById("engineContainer");

const historyTable = document.getElementById("historyTable");

const totalScan = document.getElementById("totalScan");
const safeCount = document.getElementById("safeCount");
const dangerCount = document.getElementById("dangerCount");
const riskAverage = document.getElementById("riskAverage");

// ---------- HISTORY ----------

let scanHistory = JSON.parse(localStorage.getItem("scanHistory")) || [];

// ---------- EVENT ----------

scanType.addEventListener("change", function(){

    if(scanType.value==="file"){

        targetInput.style.display="none";
        fileInput.hidden=false;

    }else{

        targetInput.style.display="block";
        fileInput.hidden=true;

    }

});

// ---------- SCAN BUTTON ----------

scanBtn.addEventListener("click", startScan);

// ---------- MAIN SCAN ----------

function startScan(){

    let value="";

    if(scanType.value==="file"){

        if(fileInput.files.length===0){

            alert("Please select a file.");

            return;
        }

        value=fileInput.files[0].name;

    }else{

        value=targetInput.value.trim();

        if(value===""){

            alert("Please enter a target.");

            return;

        }

    }

    loading.style.display="block";

    resultSection.style.display="none";

    engineContainer.innerHTML="";

    setTimeout(function(){

        loading.style.display="none";

        let report=analyzeTarget(value,scanType.value);

        displayResult(report);

        createEngineCards(report);

        saveHistory(report);

        updateDashboard();

    },2500);

}

// ---------- DISPLAY RESULT ----------

function displayResult(report){

    resultSection.style.display="block";

    scanTarget.innerHTML=report.target;

    riskScore.innerHTML=report.score+"%";

    riskBar.style.width=report.score+"%";

    threatType.innerHTML=report.threat;

    status.innerHTML=report.status;

    recommendation.innerHTML=report.recommendation;

    riskLevel.innerHTML=report.level;

    if(report.level==="Safe"){

        riskLevel.style.background="#00b894";

    }

    else if(report.level==="Medium"){

        riskLevel.style.background="#f1c40f";
        riskLevel.style.color="#000";

    }

    else{

        riskLevel.style.background="#e74c3c";

    }

}

// ---------- SAVE HISTORY ----------

function saveHistory(report){

    scanHistory.unshift({

        target:report.target,

        type:report.type,

        score:report.score,

        status:report.level,

        date:new Date().toLocaleString()

    });

    if(scanHistory.length>20){

        scanHistory.pop();

    }

    localStorage.setItem(

        "scanHistory",

        JSON.stringify(scanHistory)

    );

    renderHistory();

}

// ---------- HISTORY TABLE ----------

function renderHistory(){

    historyTable.innerHTML="";

    scanHistory.forEach(function(item){

        historyTable.innerHTML+=`

        <tr>

            <td>${item.target}</td>

            <td>${item.type}</td>

            <td>${item.score}%</td>

            <td>${item.status}</td>

            <td>${item.date}</td>

        </tr>

        `;

    });

}

// ---------- DASHBOARD ----------

function updateDashboard(){

    totalScan.innerHTML=scanHistory.length;

    let safe=0;

    let danger=0;

    let totalRisk=0;

    scanHistory.forEach(function(item){

        totalRisk+=item.score;

        if(item.score<35){

            safe++;

        }else{

            danger++;

        }

    });

    safeCount.innerHTML=safe;

    dangerCount.innerHTML=danger;

    if(scanHistory.length===0){

        riskAverage.innerHTML="0%";

    }

    else{

        riskAverage.innerHTML=

        Math.round(totalRisk/scanHistory.length)+"%";

    }

}

// ---------- INITIALIZE ----------

renderHistory();

updateDashboard();
// ==========================================
// PHISHGUARD - SCRIPT.JS (PART 2)
// Threat Detection & Security Engines
// ==========================================

// ---------- MAIN ANALYZER ----------

function analyzeTarget(target, type){

    let score = 0;

    let threat = "None";

    let level = "Safe";

    let status = "Clean";

    let recommendation = "Safe to visit.";

    let text = target.toLowerCase();

    // URL Scan
    if(type==="url"){

        score += checkURL(text);

    }

    // Domain Scan
    else if(type==="domain"){

        score += checkDomain(text);

    }

    // IP Scan
    else if(type==="ip"){

        score += checkIP(text);

    }

    // File Scan
    else{

        score += checkFile(text);

    }

    // Keyword Analysis
    score += keywordDetection(text);

    // URL Length
    if(text.length>120){

        score += 10;

    }

    // HTTP instead HTTPS
    if(text.startsWith("http://")){

        score += 15;

    }

    // @ Symbol
    if(text.includes("@")){

        score += 20;

    }

    // Too many dots
    let dots=(text.match(/\./g)||[]).length;

    if(dots>4){

        score += 10;

    }

    if(score>100){

        score=100;

    }

    // Risk Level

    if(score<30){

        level="Safe";
        threat="None";
        status="No Threat";
        recommendation="Safe to use.";

    }

    else if(score<60){

        level="Medium";
        threat="Suspicious";
        status="Potential Threat";
        recommendation="Proceed carefully.";

    }

    else{

        level="Danger";
        threat="Phishing / Malware";
        status="High Risk";
        recommendation="Avoid this target.";

    }

    return{

        target:target,
        type:type,
        score:score,
        level:level,
        threat:threat,
        status:status,
        recommendation:recommendation

    };

}

// ==========================================
// URL CHECK
// ==========================================

function checkURL(url){

    let risk=0;

    if(url.includes("login")) risk+=15;

    if(url.includes("verify")) risk+=20;

    if(url.includes("secure")) risk+=10;

    if(url.includes("update")) risk+=15;

    if(url.includes("bank")) risk+=20;

    if(url.includes("paypal")) risk+=20;

    if(url.includes("free")) risk+=10;

    if(url.includes("bonus")) risk+=15;

    return risk;

}

// ==========================================
// DOMAIN CHECK
// ==========================================

function checkDomain(domain){

    let risk=0;

    const badDomains=[

        ".xyz",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".click",
        ".zip",
        ".country"

    ];

    badDomains.forEach(function(item){

        if(domain.endsWith(item)){

            risk+=25;

        }

    });

    return risk;

}

// ==========================================
// IP CHECK
// ==========================================

function checkIP(ip){

    let risk=0;

    if(ip.startsWith("192.168")){

        return 0;

    }

    if(ip.startsWith("10.")){

        return 0;

    }

    if(ip.startsWith("172.")){

        return 0;

    }

    risk+=20;

    return risk;

}

// ==========================================
// FILE CHECK
// ==========================================

function checkFile(file){

    let risk=0;

    const dangerous=[

        ".exe",

        ".bat",

        ".cmd",

        ".scr",

        ".vbs",

        ".ps1",

        ".dll",

        ".jar"

    ];

    dangerous.forEach(function(ext){

        if(file.endsWith(ext)){

            risk+=45;

        }

    });

    return risk;

}

// ==========================================
// KEYWORD DETECTION
// ==========================================

function keywordDetection(text){

    let score=0;

    const keywords=[

        "password",

        "bank",

        "paypal",

        "credit",

        "verify",

        "account",

        "security",

        "login",

        "update",

        "invoice",

        "bitcoin",

        "wallet",

        "gift",

        "bonus",

        "winner",

        "urgent",

        "confirm",

        "reset",

        "payment",

        "apple",

        "amazon",

        "microsoft",

        "google"

    ];

    keywords.forEach(function(word){

        if(text.includes(word)){

            score+=8;

        }

    });

    return score;

}

// ==========================================
// ENGINE RESULTS
// ==========================================

function createEngineCards(report){

    engineContainer.innerHTML="";

    const engines=[

        
    ];

    engines.forEach(function(name){

        let verdict="Clean";

        let cls="clean";

        if(report.score>=60){

            verdict="Malicious";
            cls="danger";

        }

        else if(report.score>=30){

            verdict="Suspicious";
            cls="warning";

        }

        engineContainer.innerHTML+=`

        <div class="engineCard">

            <h3>${name}</h3>

            <p>

            Verdict :

            <span class="${cls}">

            ${verdict}

            </span>

            </p>

            <p>

            Confidence :

            ${Math.floor(Math.random()*20)+80}%

            </p>

        </div>

        `;

    });

}
// ==========================================
// PHISHGUARD - SCRIPT.JS (PART 3)
// Initialization, Utilities & Extra Features
// ==========================================

// ---------- CLEAR HISTORY ----------

function clearHistory() {

    if (confirm("Clear all scan history?")) {

        scanHistory = [];

        localStorage.removeItem("scanHistory");

        renderHistory();

        updateDashboard();

        alert("History cleared successfully.");

    }

}

// ---------- EXPORT HISTORY ----------

function exportHistory() {

    if (scanHistory.length === 0) {

        alert("No scan history available.");

        return;

    }

    const data = JSON.stringify(scanHistory, null, 2);

    const blob = new Blob([data], {

        type: "application/json"

    });

    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");

    a.href = url;

    a.download = "phishguard_scan_history.json";

    a.click();

    URL.revokeObjectURL(url);

}

// ---------- IMPORT HISTORY ----------

function importHistory(file) {

    const reader = new FileReader();

    reader.onload = function (e) {

        try {

            const data = JSON.parse(e.target.result);

            if (Array.isArray(data)) {

                scanHistory = data;

                localStorage.setItem(

                    "scanHistory",

                    JSON.stringify(scanHistory)

                );

                renderHistory();

                updateDashboard();

                alert("History Imported.");

            }

        }

        catch {

            alert("Invalid History File.");

        }

    };

    reader.readAsText(file);

}

// ---------- RANDOM SECURITY TIP ----------

const securityTips = [

    "Always use HTTPS websites.",

    "Never share your OTP with anyone.",

    "Enable Two-Factor Authentication.",

    "Avoid clicking unknown email links.",

    "Keep Windows Defender updated.",

    "Use strong and unique passwords.",

    "Never download cracked software.",

    "Scan files before opening them.",

    "Keep your browser updated.",

    "Don't trust shortened URLs."

];

function showSecurityTip() {

    const random = Math.floor(

        Math.random() * securityTips.length

    );

    console.log(

        "Security Tip:",

        securityTips[random]

    );

}

// ---------- AUTO ANIMATION ----------

window.addEventListener("scroll", function () {

    document.querySelectorAll(

        ".card,.engineCard,.report"

    ).forEach(function (element) {

        const position =

            element.getBoundingClientRect().top;

        if (position < window.innerHeight - 100) {

            element.style.opacity = "1";

            element.style.transform = "translateY(0px)";

        }

    });

});

// ---------- INITIAL STYLE ----------

document.querySelectorAll(

    ".card,.engineCard,.report"

).forEach(function (element) {

    element.style.opacity = "0";

    element.style.transform = "translateY(40px)";

    element.style.transition = "0.7s";

});

// ---------- ENTER KEY SUPPORT ----------

targetInput.addEventListener(

    "keypress",

    function (e) {

        if (e.key === "Enter") {

            startScan();

        }

    }

);

// ---------- PAGE LOAD ----------

window.onload = function () {

    renderHistory();

    updateDashboard();

    showSecurityTip();

};

// ---------- DEMO DATA ----------

if (scanHistory.length === 0) {

    scanHistory.push({

        target: "https://google.com",

        type: "url",

        score: 2,

        status: "Safe",

        date: new Date().toLocaleString()

    });

    scanHistory.push({

        target: "paypal-login-security.xyz",

        type: "domain",

        score: 82,

        status: "Danger",

        date: new Date().toLocaleString()

    });

    localStorage.setItem(

        "scanHistory",

        JSON.stringify(scanHistory)

    );

    renderHistory();

    updateDashboard();

}

console.log(

    "%cPhishGuard Loaded Successfully",

    "color:cyan;font-size:18px;font-weight:bold;"

);

console.log(

    "Cyber Security Scanner Ready."

);

// ==========================================
// END OF SCRIPT.JS
// ==========================================
