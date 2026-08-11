import os
import json
import subprocess
import ipaddress
import threading
import re
import time
import socket
import shutil
import queue
import uuid
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from flask import Flask, render_template_string, request, Response, jsonify, make_response, send_file

app = Flask(__name__)

scan_state = {
    "is_running": False,
    "pause_event": threading.Event(),
    "results": {},
    "internet_error": False,
    "disconnected_time": None,
    "connected_time": None,
    "current_ip": None  # Cari skan olunan IP-ni izləmək üçün
}
scan_state["pause_event"].set()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pentest Real-Time Masscanner Pro</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <style>
        body { background-color: #0b0f19; color: #e5e7eb; font-family: 'Courier New', Courier, monospace; }
        .scanning-border { border: 2px solid #f59e0b; box-shadow: 0 0 10px rgba(245, 158, 11, 0.2); }
        .completed-border { border: 1px solid #334155; }
        .paused-border { border: 2px solid #3b82f6; box-shadow: 0 0 10px rgba(59, 130, 246, 0.2); }
        .rescanning-border { border: 2px solid #a855f7; box-shadow: 0 0 10px rgba(168, 85, 247, 0.2); }
    </style>
</head>
<body class="p-8">
    <div class="max-w-7xl mx-auto">
        <div class="border-b border-slate-800 pb-4 mb-6 flex justify-between items-center">
            <div>
                <h1 class="text-2xl font-bold text-rose-500">⚡ FULL-PORT MASSCANNER PRO</h1>
                <p class="text-xs text-slate-500 mt-1">Network-Aware Subnet Scanner with Resilience Controls</p>
            </div>
            <div class="text-right text-xs text-slate-400">
                Running on: <span class="text-yellow-500 font-bold">localhost:9998</span>
            </div>
        </div>

        <div class="bg-slate-900/50 border border-slate-800 p-6 rounded-xl mb-6 shadow-xl backdrop-blur-sm">
            <div class="grid grid-cols-1 md:grid-cols-6 gap-4 items-end">
                <div class="md:col-span-2">
                    <label class="block text-xs font-bold text-slate-400 mb-2">TARGET SUBNET / CIDR</label>
                    <input type="text" id="subnet" placeholder="192.168.1.0/24"
                           class="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-rose-400 focus:outline-none focus:border-rose-500">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-400 mb-2">START IP (LAST OCTET)</label>
                    <input type="number" id="start_octet" placeholder="e.g. 29" min="1" max="254"
                           class="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-amber-400 focus:outline-none focus:border-amber-500">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-400 mb-2">CONCURRENT HOSTS</label>
                    <input type="number" id="workers" value="3" min="1" max="50"
                           class="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-emerald-400 focus:outline-none focus:border-emerald-500">
                </div>
                <div>
                    <button onclick="startScan()" id="scanBtn"
                            class="w-full bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold py-2 px-4 rounded text-sm tracking-wider cursor-pointer transition">
                        START SCAN
                    </button>
                </div>
                <div class="flex gap-2">
                    <button onclick="togglePause()" id="pauseBtn" disabled
                            class="w-1/2 bg-slate-800 text-slate-500 font-bold py-2 px-2 rounded text-xs tracking-wider opacity-50 cursor-not-allowed transition">
                        PAUSE
                    </button>
                    <button onclick="stopScan()" id="stopBtn" disabled
                            class="w-1/2 bg-slate-800 text-slate-500 font-bold py-2 px-2 rounded text-xs tracking-wider opacity-50 cursor-not-allowed transition">
                        STOP
                    </button>
                </div>
            </div>
            
            <div class="flex justify-between items-center border-t border-slate-800/60 mt-4 pt-4">
                <div class="text-[10px] text-slate-500 italic">
                    Mode: <span class="text-blue-400">TCP 1-65535 → UDP 1-65535</span> | <span id="workerLabel" class="text-blue-400">3 workers @ 1000 pkts/s</span>
                </div>
                <div class="flex gap-3 text-xs">
                    <span class="text-slate-400 self-center font-bold text-[11px]">📥 EXPORT RESULTS:</span>
                    <button onclick="downloadReport('html')" id="expHtml" disabled class="text-slate-600 font-bold hover:underline cursor-not-allowed">HTML Format</button>
                    <span class="text-slate-700">|</span>
                    <button onclick="downloadReport('txt')" id="expTxt" disabled class="text-slate-600 font-bold hover:underline cursor-not-allowed">TXT (IP:Port)</button>
                </div>
            </div>
        </div>

        <div id="networkAlertBox" class="hidden mb-6 transition-all duration-500"></div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
            
            <div class="lg:col-span-3 space-y-4">
                <div class="flex justify-between items-center">
                    <h2 class="text-lg font-bold text-slate-300 flex items-center gap-2">
                        <span>📋 Scan Targets & Live Results</span>
                        <span id="statusIndicator" class="hidden text-xs bg-rose-500/10 text-rose-400 px-2 py-0.5 rounded border border-rose-500/20 animate-pulse">PROCESSING...</span>
                    </h2>
                    <button onclick="document.getElementById('results').innerHTML = ''" class="text-xs text-rose-400 hover:underline cursor-pointer">Clear Results</button>
                </div>
                
                <div id="results" class="space-y-4">
                    </div>
            </div>

            <div class="lg:col-span-1 space-y-4">
                <div class="bg-slate-900/60 border border-slate-800 p-4 rounded-xl shadow-md">
                    <h3 class="text-xs font-bold text-slate-400 tracking-wider uppercase mb-3 border-b border-slate-800 pb-2 flex items-center gap-1.5">
                        <span class="w-2 h-2 rounded-full bg-blue-500"></span> NETWORK TIMELOG
                    </h3>
                    <div class="space-y-2 text-xs font-mono">
                        <div>
                            <span class="text-slate-500">Disconnected:</span>
                            <span id="logDisconnected" class="text-rose-400 font-bold float-right">--:--:--</span>
                        </div>
                        <div>
                            <span class="text-slate-500">Reconnected:</span>
                            <span id="logConnected" class="text-emerald-400 font-bold float-right">--:--:--</span>
                        </div>
                    </div>
                </div>

                <div class="bg-slate-900/60 border border-slate-800 p-4 rounded-xl shadow-md flex flex-col h-[400px]">
                    <h3 class="text-xs font-bold text-slate-400 tracking-wider uppercase mb-2 flex items-center gap-1.5">
                        📝 PENTEST SESSION NOTES
                    </h3>
                    <textarea placeholder="Write scratchpad notes, raw flags, or dynamic findings here..." 
                              class="w-full flex-grow bg-slate-950 border border-slate-800 text-emerald-400 font-mono text-xs p-3 rounded-lg focus:outline-none focus:border-emerald-700 resize-y placeholder-slate-700"></textarea>
                    <div class="text-[10px] text-slate-600 mt-2 italic text-right">Auto-expanding workspace scratchpad</div>
                </div>
            </div>

        </div>
    </div>

    <script>
        let eventSource = null;
        let isPaused = false;
        let netCheckInterval = null;

        function formatIpId(ip) {
            return 'ip-' + ip.split('.').join('-');
        }

        const PORT_LIMIT = 30;   // how many port badges to show before collapsing the rest

        function makePortBadge(p) {
            const badge = document.createElement('span');
            badge.className = p.state === 'open'
                ? "px-3 py-1.5 bg-rose-950/40 border border-rose-800/60 text-rose-400 font-bold rounded text-xs tracking-wider uppercase"
                : "px-3 py-1.5 bg-amber-950/40 border border-amber-800/60 text-amber-400 font-bold rounded text-xs tracking-wider uppercase";
            let text = `${p.port}/${p.proto} (${p.state})`;
            if (p.service) text += ` · ${p.service}`;
            badge.innerText = text;
            return badge;
        }

        // Renders port badges into a container, showing at most PORT_LIMIT and hiding the
        // rest behind a "Show all" toggle pinned to the bottom-right of the host card.
        function renderPorts(portsContainer, ports, ipId) {
            portsContainer.innerHTML = '';
            portsContainer.className = "flex flex-wrap gap-2.5 pt-1";

            if (!ports || ports.length === 0) {
                portsContainer.innerHTML = '<span class="text-slate-500 font-sans italic text-xs pl-1">No open or filtered ports identified.</span>';
                return;
            }

            ports.slice(0, PORT_LIMIT).forEach(p => portsContainer.appendChild(makePortBadge(p)));

            if (ports.length > PORT_LIMIT) {
                const extraClass = 'extra-port-' + ipId;
                ports.slice(PORT_LIMIT).forEach(p => {
                    const badge = makePortBadge(p);
                    badge.classList.add(extraClass, 'hidden');
                    portsContainer.appendChild(badge);
                });

                const toggleWrap = document.createElement('div');
                toggleWrap.className = "w-full flex justify-end mt-1";
                const btn = document.createElement('button');
                btn.className = "text-[11px] font-bold bg-slate-800/60 hover:bg-slate-700/60 text-slate-300 border border-slate-700 px-2.5 py-1 rounded transition cursor-pointer";
                btn.innerText = `⤢ Show all ${ports.length} ports (+${ports.length - PORT_LIMIT})`;
                let expanded = false;
                btn.onclick = () => {
                    expanded = !expanded;
                    portsContainer.querySelectorAll('.' + extraClass).forEach(el => el.classList.toggle('hidden', !expanded));
                    btn.innerText = expanded ? '⤡ Show fewer' : `⤢ Show all ${ports.length} ports (+${ports.length - PORT_LIMIT})`;
                };
                toggleWrap.appendChild(btn);
                portsContainer.appendChild(toggleWrap);
            }
        }

        function buildActionControls(ip) {
            const ipId = formatIpId(ip);
            return `
                <div class="flex items-center gap-2" id="controls-container-${ipId}">
                    <select id="tool-${ipId}" class="bg-slate-950 border border-slate-800 text-[11px] text-amber-400 px-2 py-1 rounded focus:outline-none cursor-pointer">
                        <option value="nmap_deep">Nmap Deep (-sC -sV TCP + -sU UDP on found ports)</option>
                        <option value="masscan_tcp">Masscan TCP Rescan (full)</option>
                        <option value="masscan_udp">Masscan UDP Rescan (full)</option>
                    </select>
                    <button onclick="triggerRescan('${ip}')" class="text-[11px] font-bold bg-purple-900/40 hover:bg-purple-800/60 text-purple-300 border border-purple-700/50 px-2.5 py-1 rounded transition cursor-pointer flex items-center gap-1">
                        🔄 Rescan
                    </button>
                </div>
            `;
        }

        function monitorNetworkStatus() {
            if (netCheckInterval) clearInterval(netCheckInterval);
            
            netCheckInterval = setInterval(() => {
                fetch('/check-network')
                .then(res => res.json())
                .then(data => {
                    const alertBox = document.getElementById('networkAlertBox');
                    
                    if (data.internet_error) {
                        isPaused = true;
                        document.getElementById('pauseBtn').innerText = "RESUME";
                        document.getElementById('pauseBtn').className = "w-1/2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold py-2 px-2 rounded text-xs tracking-wider transition cursor-pointer";
                        
                        // Update logs
                        if (data.disconnected_time) document.getElementById('logDisconnected').innerText = data.disconnected_time;

                        alertBox.className = "block bg-rose-950/40 border border-rose-800 text-rose-400 rounded-xl p-5 shadow-lg backdrop-blur-sm";
                        alertBox.innerHTML = `
                            <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                                <div>
                                    <div class="text-sm font-bold tracking-wider flex items-center gap-2">
                                        <span class="w-2.5 h-2.5 bg-rose-500 rounded-full animate-ping"></span>
                                        🚨 INTERNET CONNECTION LOST! SCAN MODE PAUSED AUTOMATICALLY
                                    </div>
                                    <p class="text-xs text-slate-400 mt-1">System halted to prevent data loss. Disconnection Time: <span class="text-rose-500 font-bold">${data.disconnected_time}</span></p>
                                </div>
                                <div class="text-xs text-rose-400 bg-rose-950/60 px-3 py-1.5 rounded border border-rose-800/50 uppercase tracking-widest animate-pulse">
                                    Waiting for Network...
                                </div>
                            </div>
                        `;
                    } else if (!data.internet_error && data.disconnected_time) {
                        if (data.connected_time) document.getElementById('logConnected').innerText = data.connected_time;

                        alertBox.className = "block bg-emerald-950/40 border border-emerald-800 text-emerald-400 rounded-xl p-5 shadow-lg backdrop-blur-sm";
                        alertBox.innerHTML = `
                            <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                                <div>
                                    <div class="text-sm font-bold tracking-wider flex items-center gap-2">
                                        <span class="w-2.5 h-2.5 bg-emerald-400 rounded-full"></span>
                                        🟢 INTERNET RESTORED!
                                    </div>
                                    <p class="text-xs text-slate-400 mt-1">Reconnection Time: <span class="text-emerald-400 font-bold">${data.connected_time}</span>. Click the button to resume safely.</p>
                                </div>
                                <div>
                                    <button onclick="resumeFromNetwork()" class="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold py-1.5 px-4 rounded text-xs tracking-wider shadow transition cursor-pointer">
                                        ▶️ CONTINUE SCAN
                                    </button>
                                </div>
                            </div>
                        `;
                    } else {
                        alertBox.className = "hidden";
                    }
                });
            }, 3000);
        }

        function resumeFromNetwork() {
            fetch('/resume-scan', { method: 'POST' }).then(() => {
                isPaused = false;
                document.getElementById('networkAlertBox').className = "hidden";
                const pauseBtn = document.getElementById('pauseBtn');
                pauseBtn.innerText = "PAUSE";
                pauseBtn.className = "w-1/2 bg-blue-600 hover:bg-blue-500 text-slate-950 font-bold py-2 px-2 rounded text-xs tracking-wider transition cursor-pointer";
            });
        }

        function triggerRescan(ip) {
            const ipId = formatIpId(ip);
            const tool = document.getElementById(`tool-${ipId}`).value;
            const ipDiv = document.getElementById(ipId);
            const portsContainer = document.getElementById(`ports-container-${ipId}`);
            const controlsContainer = document.getElementById(`controls-container-${ipId}`);
            
            ipDiv.className = "bg-slate-900 rescanning-border rounded-lg p-5 shadow-md block clear-both transition-all duration-300";
            
            const statusSpan = ipDiv.querySelector('.text-emerald-400, .text-amber-500, .text-rose-500');
            if (statusSpan) {
                statusSpan.className = "text-xs font-semibold text-purple-400 tracking-wider animate-pulse bg-purple-500/5 px-2.5 py-1 rounded border border-purple-500/10 uppercase";
                statusSpan.innerText = `🔄 Rescanning with profile: ${tool.toUpperCase()}...`;
            }

            controlsContainer.style.opacity = "0.3";
            controlsContainer.style.pointerEvents = "none";
            portsContainer.innerHTML = '<span class="text-slate-500 font-sans italic text-xs pl-1">Executing custom footprinting template, please wait...</span>';

            fetch('/run-single-rescan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip, tool: tool })
            })
            .then(res => res.json())
            .then(data => {
                controlsContainer.style.opacity = "1";
                controlsContainer.style.pointerEvents = "auto";

                if (data.error) {
                    ipDiv.className = "bg-slate-900 border border-rose-900 rounded-lg p-5 shadow-sm block clear-both transition-all duration-300";
                    if (statusSpan) {
                        statusSpan.className = "text-xs font-bold text-rose-400 bg-rose-500/10 px-2.5 py-1 rounded border border-rose-500/20 tracking-wider animate-none";
                        statusSpan.innerText = "⚠️ RESCAN FAILED";
                    }
                    portsContainer.innerHTML = '<span class="text-rose-400 font-sans text-xs pl-1">' + data.error + '</span>';
                    return;
                }

                ipDiv.className = "bg-slate-900/80 completed-border rounded-lg p-5 shadow-sm block clear-both transition-all duration-300 hover:border-slate-700";

                if (statusSpan) {
                    statusSpan.className = "text-xs font-bold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20 tracking-wider animate-none";
                    statusSpan.innerText = "✅ SCAN COMPLETED";
                }

                renderPorts(portsContainer, data.ports, ipId);

                // For nmap scans, expose a button that opens the saved full report in a new tab.
                const oldReport = controlsContainer.querySelector('.nmap-report-btn');
                if (oldReport) oldReport.remove();
                if (data.scan_id) {
                    const report = document.createElement('a');
                    report.className = "nmap-report-btn text-[11px] font-bold bg-sky-900/40 hover:bg-sky-800/60 text-sky-300 border border-sky-700/50 px-2.5 py-1 rounded transition cursor-pointer flex items-center gap-1";
                    report.href = `/nmap-result/${data.scan_id}`;
                    report.target = "_blank";
                    report.innerText = data.screenshots ? `📄 Full nmap report (📸 ${data.screenshots})` : "📄 Full nmap report";
                    controlsContainer.appendChild(report);
                }
            })
            .catch(() => {
                ipDiv.className = "bg-slate-900 border border-rose-900 rounded-lg p-5 shadow-sm";
                controlsContainer.style.opacity = "1";
                controlsContainer.style.pointerEvents = "auto";
            });
        }

        function startScan() {
            const subnet = document.getElementById('subnet').value;
            const startOctet = document.getElementById('start_octet').value;
            const workers = document.getElementById('workers').value;
            const resultsDiv = document.getElementById('results');
            const scanBtn = document.getElementById('scanBtn');
            const stopBtn = document.getElementById('stopBtn');
            const pauseBtn = document.getElementById('pauseBtn');
            const indicator = document.getElementById('statusIndicator');

            if (!subnet) { alert('Please enter a target subnet.'); return; }

            resultsDiv.innerHTML = '';
            isPaused = false;
            
            scanBtn.disabled = true;
            scanBtn.classList.add('opacity-50', 'cursor-not-allowed');
            
            stopBtn.disabled = false;
            stopBtn.className = "w-1/2 bg-rose-700 hover:bg-rose-600 text-white font-bold py-2 px-2 rounded text-xs tracking-wider transition cursor-pointer";
            
            pauseBtn.disabled = false;
            pauseBtn.className = "w-1/2 bg-blue-600 hover:bg-blue-500 text-slate-950 font-bold py-2 px-2 rounded text-xs tracking-wider transition cursor-pointer";

            disableExports(true);
            indicator.classList.remove('hidden');
            
            // Reset network UI timers
            document.getElementById('logDisconnected').innerText = "--:--:--";
            document.getElementById('logConnected').innerText = "--:--:--";
            
            monitorNetworkStatus();

            if (workers) document.getElementById('workerLabel').innerText = `${workers} workers @ 1000 pkts/s`;

            let url = `/run-scan?subnet=${encodeURIComponent(subnet)}`;
            if (startOctet) url += `&start_octet=${encodeURIComponent(startOctet)}`;
            if (workers) url += `&workers=${encodeURIComponent(workers)}`;

            eventSource = new EventSource(url);

            eventSource.onmessage = function(event) {
                const data = JSON.parse(event.data);
                if (data.error) { showScanError(data.error); return; }
                if (data.status === 'done') { resetUI(false); return; }

                const ipId = formatIpId(data.ip);
                let ipDiv = document.getElementById(ipId);

                if (data.status === 'scanning') {
                    if (!ipDiv) {
                        ipDiv = document.createElement('div');
                        ipDiv.id = ipId;
                        ipDiv.className = "bg-slate-900 scanning-border rounded-lg p-5 shadow-md block clear-both transition-all duration-300";
                        
                        ipDiv.innerHTML = `
                            <div class="flex justify-between items-center border-b border-slate-800/80 pb-3 mb-4">
                                <div class="flex items-center gap-3">
                                    <span class="text-md font-bold text-amber-400 tracking-wide bg-slate-950 px-3 py-1 rounded border border-slate-800">${data.ip}</span>
                                    <span class="text-xs font-semibold text-amber-500 tracking-wider animate-pulse bg-amber-500/5 px-2.5 py-1 rounded border border-amber-500/10">
                                        🔍 [PHASE] -> Actively footprinting host...
                                    </span>
                                </div>
                                <div id="actions-wrapper-${ipId}">
                                    <span class="text-[10px] text-slate-500 uppercase tracking-widest">Active Thread</span>
                                </div>
                            </div>
                            <div class="text-xs text-slate-400/80 italic font-sans pl-1" id="ports-container-${ipId}">
                                Dispatching connection tracking packets over 65535 TCP/UDP ports...
                            </div>
                        `;
                        resultsDiv.appendChild(ipDiv);
                        ipDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    } else {
                        // Re-scanning (retry) triggered after network drop
                        ipDiv.className = "bg-slate-900 scanning-border rounded-lg p-5 shadow-md block clear-both transition-all duration-300";
                        const statusSpan = ipDiv.querySelector('.text-rose-400, .text-blue-400, .text-amber-500');
                        if (statusSpan) {
                            statusSpan.className = "text-xs font-semibold text-amber-500 tracking-wider animate-pulse bg-amber-500/5 px-2.5 py-1 rounded border border-amber-500/10";
                            statusSpan.innerText = "🔍 [RETRYING] -> Retrying host scan due to network drop...";
                        }
                    }
                }

                if (data.status === 'completed') {
                    if (ipDiv) {
                        ipDiv.className = "bg-slate-900/80 completed-border rounded-lg p-5 shadow-sm block clear-both transition-all duration-300 hover:border-slate-700";
                        
                        const ipSpan = ipDiv.querySelector('.text-amber-400');
                        if (ipSpan) ipSpan.className = "text-md font-bold text-slate-300 tracking-wide bg-slate-950 px-3 py-1 rounded border border-slate-800";
                        
                        const statusSpan = ipDiv.querySelector('.text-amber-500') || ipDiv.querySelector('.text-blue-400');
                        if (statusSpan) {
                            statusSpan.className = "text-xs font-bold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20 tracking-wider animate-none";
                            statusSpan.innerText = "✅ SCAN COMPLETED";
                        }

                        document.getElementById(`actions-wrapper-${ipId}`).innerHTML = buildActionControls(data.ip);

                        const portsContainer = document.getElementById(`ports-container-${ipId}`);
                        renderPorts(portsContainer, data.ports, ipId);
                    }
                }
            };
            eventSource.onerror = function() { resetUI(true); };
        }

        function togglePause() {
            const pauseBtn = document.getElementById('pauseBtn');
            if (!isPaused) {
                fetch('/pause-scan', { method: 'POST' }).then(() => {
                    isPaused = true;
                    pauseBtn.innerText = "RESUME";
                    pauseBtn.className = "w-1/2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold py-2 px-2 rounded text-xs tracking-wider transition cursor-pointer";
                    // Pause every card that is currently scanning (up to SCAN_WORKERS in parallel).
                    document.querySelectorAll('.scanning-border').forEach(activeScanning => {
                        activeScanning.classList.remove('scanning-border');
                        activeScanning.classList.add('paused-border');
                        const statusSpan = activeScanning.querySelector('.text-amber-500');
                        if (statusSpan) {
                            statusSpan.className = "text-xs font-semibold text-blue-400 tracking-wider bg-blue-500/5 px-2.5 py-1 rounded border border-blue-500/10 uppercase";
                            statusSpan.innerText = "⏸️ SCAN PAUSED";
                        }
                    });
                });
            } else {
                fetch('/resume-scan', { method: 'POST' }).then(() => {
                    isPaused = false;
                    pauseBtn.innerText = "PAUSE";
                    pauseBtn.className = "w-1/2 bg-blue-600 hover:bg-blue-500 text-slate-950 font-bold py-2 px-2 rounded text-xs tracking-wider transition cursor-pointer";
                    // Resume every paused card back to the scanning state.
                    document.querySelectorAll('.paused-border').forEach(pausedDiv => {
                        pausedDiv.classList.remove('paused-border');
                        pausedDiv.classList.add('scanning-border');
                        const statusSpan = pausedDiv.querySelector('.text-blue-400');
                        if (statusSpan) {
                            statusSpan.className = "text-xs font-semibold text-amber-500 tracking-wider animate-pulse bg-amber-500/5 px-2.5 py-1 rounded border border-amber-500/10 uppercase";
                            statusSpan.innerText = "🔍 [PHASE] -> Actively footprinting host...";
                        }
                    });
                });
            }
        }

        function stopScan() {
            if (eventSource) eventSource.close();
            if (netCheckInterval) clearInterval(netCheckInterval);
            fetch('/stop-scan', { method: 'POST' }).then(() => {
                const activeScanning = document.querySelector('.scanning-border, .paused-border');
                if (activeScanning) {
                    activeScanning.className = "bg-slate-900 border border-rose-900/50 rounded-lg p-5 shadow-sm block clear-both opacity-70";
                    const statusSpan = activeScanning.querySelector('.text-amber-500, .text-blue-400');
                    if (statusSpan) {
                        statusSpan.className = "text-xs font-bold text-rose-500 bg-rose-500/10 px-2.5 py-1 rounded border border-rose-500/20 tracking-wider";
                        statusSpan.innerText = "🛑 SCAN TERMINATED";
                    }
                }
                resetUI(true);
            });
        }

        function resetUI(interrupted) {
            if (eventSource) eventSource.close();
            if (netCheckInterval) clearInterval(netCheckInterval);
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('scanBtn').classList.remove('opacity-50', 'cursor-not-allowed');
            document.getElementById('stopBtn').disabled = true;
            document.getElementById('stopBtn').className = "w-1/2 bg-slate-800 text-slate-500 font-bold py-2 px-2 rounded text-xs tracking-wider opacity-50 cursor-not-allowed transition";
            document.getElementById('pauseBtn').disabled = true;
            document.getElementById('pauseBtn').className = "w-1/2 bg-slate-800 text-slate-500 font-bold py-2 px-2 rounded text-xs tracking-wider opacity-50 cursor-not-allowed transition";
            document.getElementById('statusIndicator').classList.add('hidden');
            document.getElementById('networkAlertBox').className = "hidden";
            
            document.querySelectorAll('[id^="actions-wrapper-"]').forEach(wrapper => {
                const ip = wrapper.id.replace('actions-wrapper-ip-', '').replace(/-/g, '.');
                if(!wrapper.querySelector('select')) {
                    wrapper.innerHTML = buildActionControls(ip);
                }
            });

            disableExports(false);
        }

        function disableExports(status) {
            const h = document.getElementById('expHtml');
            const t = document.getElementById('expTxt');
            if(status) {
                h.disabled = true; h.className = "text-slate-600 font-bold hover:underline cursor-not-allowed";
                t.disabled = true; t.className = "text-slate-600 font-bold hover:underline cursor-not-allowed";
            } else {
                h.disabled = false; h.className = "text-emerald-400 font-bold hover:underline cursor-pointer";
                t.disabled = false; t.className = "text-amber-400 font-bold hover:underline cursor-pointer";
            }
        }

        function showScanError(message) {
            const resultsDiv = document.getElementById('results');
            const errDiv = document.createElement('div');
            errDiv.className = "bg-rose-950/40 border border-rose-800 text-rose-300 rounded-lg p-4 text-sm block clear-both";
            errDiv.innerText = "⚠️ " + message;
            resultsDiv.appendChild(errDiv);
        }

        function downloadReport(format) { window.location.href = `/export-report?format=${format}`; }
    </script>
</body>
</html>
"""

def check_internet():
    try:
        socket.setdefaulttimeout(2)
        socket.gethostbyname("google.com")
        return True
    except socket.gaierror:
        return False

def parse_masscan_stdout(stdout_text):
    ports = []
    pattern = r"Discovered open port (\d+)/(tcp|udp) on"
    matches = re.findall(pattern, stdout_text)
    for port, proto in matches:
        ports.append({'port': int(port), 'proto': proto, 'state': 'open'})
    return ports

def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False

def parse_nmap_xml(stdout_text):
    ports = []
    if not stdout_text or not stdout_text.strip():
        return ports
    try:
        root = ET.fromstring(stdout_text.strip())
    except ET.ParseError:
        return ports
    for port_elem in root.findall(".//port"):
        state_elem = port_elem.find('state')
        port_id = port_elem.get('portid')
        if state_elem is None or port_id is None:
            continue
        state = state_elem.get('state') or ''
        # UDP is often reported as "open|filtered"; keep anything that starts with "open" plus "filtered".
        if state.startswith('open') or state == 'filtered':
            svc_elem = port_elem.find('service')
            service = None
            if svc_elem is not None:
                # Build a readable service label: "http" or "http (Apache httpd 2.4)".
                name = svc_elem.get('name')
                product = svc_elem.get('product')
                version = svc_elem.get('version')
                if name:
                    detail = " ".join(x for x in (product, version) if x)
                    service = f"{name} ({detail})" if detail else name
            ports.append({
                'port': int(port_id),
                'proto': port_elem.get('protocol'),
                'state': state,
                'service': service,
            })
    return ports

# --- Persistence (SQLite) ------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS nmap_scans (
            id               TEXT PRIMARY KEY,
            ip               TEXT NOT NULL,
            tool             TEXT,
            created_at       TEXT NOT NULL,
            command          TEXT,
            raw_output       TEXT,
            ports_json       TEXT,
            screenshots_json TEXT
        )
    """)
    # Migrate older databases that predate the screenshots column.
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(nmap_scans)")]
    if "screenshots_json" not in cols:
        conn.execute("ALTER TABLE nmap_scans ADD COLUMN screenshots_json TEXT")
    conn.commit()
    conn.close()

init_db()

# --- Web screenshots -----------------------------------------------------
SHOTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")
os.makedirs(SHOTS_DIR, exist_ok=True)

# TCP ports we treat as web even when nmap can't name the service.
WEB_PORTS = {80, 81, 443, 591, 3000, 5000, 7001, 8000, 8008, 8080, 8081,
             8443, 8888, 9000, 9090, 9200, 10000}

def find_browser():
    # Returns (path, kind) for a headless-screenshot-capable browser, or (None, None).
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"):
        path = shutil.which(name)
        if path:
            return path, "chromium"
    for name in ("firefox", "firefox-esr"):
        path = shutil.which(name)
        if path:
            return path, "firefox"
    return None, None

def web_url_for(ip, port_dict):
    # Decides whether a port is a web app and builds its URL (http/https).
    if port_dict.get('proto') != 'tcp':
        return None
    name = (port_dict.get('service') or '').lower()
    port = port_dict['port']
    if 'http' not in name and port not in WEB_PORTS:
        return None
    https = ('https' in name) or ('ssl' in name) or port in (443, 8443)
    scheme = 'https' if https else 'http'
    return f"{scheme}://{ip}:{port}"

def capture_web_screenshots(ip, ports, scan_id):
    # Screenshots every web port; returns (list_of_shot_dicts, note_string).
    browser, kind = find_browser()
    if not browser:
        return [], "No headless browser found (install chromium or firefox) — screenshots skipped."

    shots = []
    for p in ports:
        url = web_url_for(ip, p)
        if not url:
            continue
        fname = f"{scan_id}_{p['proto']}_{p['port']}.png"
        out = os.path.join(SHOTS_DIR, fname)
        try:
            if kind == "chromium":
                cmd = [browser, "--headless", "--disable-gpu", "--no-sandbox",
                       "--hide-scrollbars", "--ignore-certificate-errors",
                       "--virtual-time-budget=6000", "--window-size=1280,900",
                       f"--screenshot={out}", url]
                subprocess.run(cmd, capture_output=True, timeout=45, check=False)
            else:  # firefox — use a throwaway profile so it won't clash with a running instance
                profile = tempfile.mkdtemp(prefix="ff-shot-")
                cmd = [browser, "--headless", "--new-instance", "--profile", profile,
                       "--window-size=1280,900", "--screenshot", out, url]
                subprocess.run(cmd, capture_output=True, timeout=45, check=False,
                               env={**os.environ, "MOZ_HEADLESS": "1"})
                shutil.rmtree(profile, ignore_errors=True)
        except Exception:
            continue
        if os.path.exists(out) and os.path.getsize(out) > 0:
            shots.append({"port": p['port'], "proto": p['proto'], "url": url, "file": fname})
    note = "" if shots else "No web services detected, or the browser failed to capture them."
    return shots, note

# --- Scan tuning ---------------------------------------------------------
SCAN_WORKERS = 3           # how many IPs to scan in parallel (raise once mirrored networking is stable)
MASSCAN_RATE = "1000"      # masscan packet rate (pkts/s) per process

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/check-network')
def check_network():
    is_connected = check_internet()
    now_str = datetime.now().strftime("%H:%M:%S")

    if not is_connected:
        if not scan_state["internet_error"]:
            scan_state["internet_error"] = True
            scan_state["disconnected_time"] = now_str
            scan_state["connected_time"] = None
            scan_state["pause_event"].clear()
    else:
        if scan_state["internet_error"]:
            scan_state["internet_error"] = False
            scan_state["connected_time"] = now_str

    return jsonify({
        "internet_error": scan_state["internet_error"] or (scan_state["disconnected_time"] is not None and scan_state["connected_time"] is None),
        "disconnected_time": scan_state["disconnected_time"],
        "connected_time": scan_state["connected_time"]
    })

@app.route('/run-scan')
def run_scan():
    subnet_str = request.args.get('subnet')
    start_octet = request.args.get('start_octet', None)

    # How many hosts to scan in parallel; falls back to the default and is clamped to a sane range.
    try:
        num_workers = int(request.args.get('workers', SCAN_WORKERS))
    except (TypeError, ValueError):
        num_workers = SCAN_WORKERS
    num_workers = max(1, min(num_workers, 50))

    scan_state["is_running"] = True
    scan_state["pause_event"].set()
    scan_state["results"] = {}
    scan_state["internet_error"] = False
    scan_state["disconnected_time"] = None
    scan_state["connected_time"] = None

    def generate():
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            if start_octet and start_octet.isdigit():
                start_val = int(start_octet)
                hosts = [h for h in hosts if int(h.split('.')[-1]) >= start_val]
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            yield "data: {\"status\": \"done\"}\n\n"
            return

        if shutil.which("masscan") is None:
            msg = "masscan not found on PATH. Install it (e.g. 'sudo apt install masscan') and run this tool with root/sudo."
            yield f"data: {json.dumps({'error': msg})}\n\n"
            yield "data: {\"status\": \"done\"}\n\n"
            return

        # Worker thread-lər nəticələri bu növbəyə qoyur, generator isə onları UI-a axıdır.
        event_q = queue.Queue()

        def masscan_phase(ip, port_spec):
            # Bir masscan fazasını icra edir; internet kəsiləndə həmin fazanı təkrar yoxlayır.
            while True:
                scan_state["pause_event"].wait()   # internet yoxdursa burada kilidlənir
                if not scan_state["is_running"]:
                    return []
                try:
                    res = subprocess.run(
                        ["masscan", ip, port_spec, "--rate", MASSCAN_RATE],
                        capture_output=True, text=True, check=False
                    )
                except Exception:
                    return []
                # Skan əsnasında internet gedibsə və nəticə boşdursa, qəbul etmə - pause edib təkrar yoxla.
                if not check_internet() and not res.stdout.strip():
                    scan_state["pause_event"].clear()
                    continue
                return parse_masscan_stdout(res.stdout)

        def scan_one(ip):
            scan_state["pause_event"].wait()
            if not scan_state["is_running"]:
                return
            event_q.put({'ip': ip, 'status': 'scanning', 'ports': []})
            ports = masscan_phase(ip, "-p1-65535")                    # 1) TCP full-port
            if scan_state["is_running"]:
                ports += masscan_phase(ip, "-pU:1-65535")             # 2) UDP full-port
            scan_state["results"][ip] = ports
            event_q.put({'ip': ip, 'status': 'completed', 'ports': ports})

        def run_pool():
            try:
                with ThreadPoolExecutor(max_workers=num_workers) as ex:
                    for _ in ex.map(scan_one, hosts):
                        pass
            finally:
                event_q.put({'status': 'done'})   # nə olursa olsun UI-ə bitmə siqnalı göndər

        threading.Thread(target=run_pool, daemon=True).start()

        while True:
            item = event_q.get()
            yield f"data: {json.dumps(item)}\n\n"
            if item.get('status') == 'done':
                break

        scan_state["is_running"] = False

    return Response(generate(), mimetype='text/event-stream')

def _run_nmap(ip, ports, udp=False):
    # Runs nmap against a specific set of ports (the ones masscan already found).
    # Normal output goes to stdout (kept for the human-readable report, incl. -sC script results);
    # XML goes to a temp file so we can parse ports + services reliably.
    port_spec = ",".join(str(p) for p in ports)
    if udp:
        base = ["nmap", "-sU", "-sV", "-Pn", "-T4", "-p", port_spec, ip]
    else:
        base = ["nmap", "-sC", "-sV", "-Pn", "-T4", "-p", port_spec, ip]

    fd, xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    cmd = base + ["-oX", xml_path, "-oN", "-"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        normal_out = res.stdout or ""
        if res.stderr:
            normal_out += "\n" + res.stderr
        with open(xml_path) as f:
            parsed = parse_nmap_xml(f.read())
    except Exception as e:
        normal_out = f"nmap execution error: {e}"
        parsed = []
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass
    return normal_out, parsed, " ".join(cmd)

def run_nmap_rescan(ip, tool):
    if shutil.which("nmap") is None:
        return jsonify({"error": "nmap not found on PATH. Please install it."}), 400

    prior = scan_state["results"].get(ip, [])
    tcp_ports = sorted({p['port'] for p in prior if p.get('proto') == 'tcp'})
    udp_ports = sorted({p['port'] for p in prior if p.get('proto') == 'udp'})

    if not tcp_ports and not udp_ports:
        return jsonify({"error": "No masscan-discovered ports for this host yet. Run a masscan scan first so nmap knows what to inspect."}), 400

    discovered_ports = []
    raw_sections = []
    commands = []

    if tcp_ports:
        out, parsed, cmd = _run_nmap(ip, tcp_ports, udp=False)
        discovered_ports += parsed
        raw_sections.append(f"# TCP service/script scan on ports: {','.join(map(str, tcp_ports))}\n{out}")
        commands.append(cmd)
    if udp_ports:
        out, parsed, cmd = _run_nmap(ip, udp_ports, udp=True)
        discovered_ports += parsed
        raw_sections.append(f"# UDP scan on ports: {','.join(map(str, udp_ports))}\n{out}")
        commands.append(cmd)

    scan_id = uuid.uuid4().hex[:12]

    # Screenshot any web apps nmap turned up, and record the browser note in the report.
    shots, shot_note = capture_web_screenshots(ip, discovered_ports, scan_id)
    if shot_note:
        raw_sections.append(f"# Web screenshots: {shot_note}")

    conn = get_db()
    conn.execute(
        "INSERT INTO nmap_scans (id, ip, tool, created_at, command, raw_output, ports_json, screenshots_json) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (scan_id, ip, tool, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         "\n".join(commands), "\n\n".join(raw_sections), json.dumps(discovered_ports),
         json.dumps(shots)),
    )
    conn.commit()
    conn.close()

    scan_state["results"][ip] = discovered_ports
    return jsonify({"ip": ip, "ports": discovered_ports, "scan_id": scan_id, "screenshots": len(shots)})

@app.route('/run-single-rescan', methods=['POST'])
def run_single_rescan():
    data = request.json
    ip = data.get('ip')
    tool = data.get('tool')
    discovered_ports = []

    if not ip: return jsonify({"error": "IP missing"}), 400
    if not is_valid_ip(ip): return jsonify({"error": "Invalid IP"}), 400

    # nmap now runs only against the ports masscan already found (TCP: -sC -sV, UDP: -sU),
    # and its full output is saved to SQLite for later viewing.
    if (tool or "").startswith("nmap"):
        return run_nmap_rescan(ip, tool)

    if shutil.which("masscan") is None:
        return jsonify({"error": "masscan not found on PATH. Please install it."}), 400

    if tool == 'masscan_tcp':
        cmd = ["masscan", ip, "-pT:1-65535", "--rate", "5000"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            discovered_ports = parse_masscan_stdout(res.stdout)
        except Exception: pass

    elif tool == 'masscan_udp':
        cmd = ["masscan", ip, "-pU:1-65535", "--rate", "5000"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            discovered_ports = parse_masscan_stdout(res.stdout)
        except Exception: pass

    scan_state["results"][ip] = discovered_ports
    return jsonify({"ip": ip, "ports": discovered_ports})

NMAP_RESULT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Report {{ scan['ip'] }} · {{ scan['id'] }}</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <style>
        body { background-color: #0b0f19; color: #e5e7eb; font-family: 'Courier New', Courier, monospace; }
        pre { white-space: pre-wrap; word-break: break-word; }
    </style>
</head>
<body class="p-8">
    <div class="max-w-5xl mx-auto space-y-6">
        <div class="border-b border-slate-800 pb-4 flex justify-between items-center">
            <div>
                <h1 class="text-2xl font-bold text-sky-400">📄 NMAP DEEP REPORT</h1>
                <p class="text-xs text-slate-500 mt-1">Host <span class="text-amber-400 font-bold">{{ scan['ip'] }}</span>
                   · scan id <span class="text-slate-300">{{ scan['id'] }}</span>
                   · {{ scan['created_at'] }}</p>
            </div>
            <a href="/scans" class="text-xs text-sky-400 hover:underline">← All saved scans</a>
        </div>

        <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
            <h2 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Ports & Services</h2>
            <div class="flex flex-wrap gap-2">
            {% for p in ports %}
                <span class="px-2.5 py-1 rounded text-xs font-bold uppercase border
                    {{ 'bg-rose-950/40 border-rose-800/60 text-rose-400' if p['state'] == 'open' else 'bg-amber-950/40 border-amber-800/60 text-amber-400' }}">
                    {{ p['port'] }}/{{ p['proto'] }} ({{ p['state'] }}){% if p['service'] %} · {{ p['service'] }}{% endif %}
                </span>
            {% else %}
                <span class="text-xs text-slate-500 italic">No open/filtered ports parsed.</span>
            {% endfor %}
            </div>
        </div>

        {% if shots %}
        <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
            <h2 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">📸 Web Screenshots</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            {% for s in shots %}
                <div class="border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
                    <a href="{{ s['url'] }}" target="_blank" class="block text-[11px] text-sky-400 hover:underline px-3 py-2 border-b border-slate-800 truncate">{{ s['url'] }}</a>
                    <a href="/screenshot/{{ s['file'] }}" target="_blank">
                        <img src="/screenshot/{{ s['file'] }}" alt="screenshot of {{ s['url'] }}" class="w-full block hover:opacity-90 transition">
                    </a>
                </div>
            {% endfor %}
            </div>
        </div>
        {% endif %}

        <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
            <h2 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Command</h2>
            <pre class="text-[11px] text-emerald-400">{{ scan['command'] }}</pre>
        </div>

        <div class="bg-slate-950 border border-slate-800 rounded-xl p-4">
            <h2 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Full Nmap Output (incl. script results)</h2>
            <pre class="text-xs text-slate-300 leading-relaxed">{{ scan['raw_output'] }}</pre>
        </div>
    </div>
</body>
</html>
"""

@app.route('/screenshot/<fname>')
def screenshot(fname):
    # Serve a saved screenshot; basename() guards against path traversal.
    path = os.path.join(SHOTS_DIR, os.path.basename(fname))
    if not os.path.isfile(path):
        return "Not found", 404
    return send_file(path, mimetype='image/png')

@app.route('/nmap-result/<scan_id>')
def nmap_result(scan_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM nmap_scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return "Scan not found.", 404
    ports = json.loads(row["ports_json"] or "[]")
    shots = json.loads((row["screenshots_json"] if "screenshots_json" in row.keys() else None) or "[]")
    return render_template_string(NMAP_RESULT_TEMPLATE, scan=row, ports=ports, shots=shots)

@app.route('/scans')
def list_scans():
    conn = get_db()
    rows = conn.execute("SELECT id, ip, tool, created_at FROM nmap_scans ORDER BY created_at DESC").fetchall()
    conn.close()
    items = "".join(
        f"<a href='/nmap-result/{r['id']}' class='block bg-slate-900/60 border border-slate-800 hover:border-sky-700 rounded-lg p-3 text-sm'>"
        f"<span class='text-amber-400 font-bold'>{r['ip']}</span> "
        f"<span class='text-slate-500'>· {r['created_at']} · {r['tool']} · {r['id']}</span></a>"
        for r in rows
    ) or "<p class='text-slate-500 text-sm italic'>No saved nmap scans yet.</p>"
    page = ("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Saved Nmap Scans</title>"
            "<script src='https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4'></script>"
            "<style>body{background:#0b0f19;color:#e5e7eb;font-family:monospace;}</style></head>"
            "<body class='p-8'><div class='max-w-3xl mx-auto space-y-3'>"
            "<h1 class='text-2xl font-bold text-sky-400 border-b border-slate-800 pb-3 mb-2'>📚 SAVED NMAP SCANS</h1>"
            f"{items}</div></body></html>")
    return page

@app.route('/pause-scan', methods=['POST'])
def pause_scan(): scan_state["pause_event"].clear(); return jsonify({"status": "paused"})

@app.route('/resume-scan', methods=['POST'])
def resume_scan():
    scan_state["internet_error"] = False
    scan_state["disconnected_time"] = None
    scan_state["connected_time"] = None
    scan_state["pause_event"].set()
    return jsonify({"status": "resumed"})

@app.route('/stop-scan', methods=['POST'])
def stop_scan():
    scan_state["is_running"] = False
    scan_state["pause_event"].set()
    for proc in ("masscan", "nmap"):
        try: subprocess.run(["pkill", proc], check=False)
        except Exception: pass
    return jsonify({"status": "stopped"})

@app.route('/export-report')
def export_report():
    fmt = request.args.get('format', 'txt')
    if fmt == 'txt':
        output = []
        for ip, ports in scan_state["results"].items():
            if ports:
                for p in ports: output.append(f"{ip}:{p['port']} ({p['proto']}/{p['state']})")
            else: output.append(f"{ip} -> No open ports found.")
        response = make_response("\n".join(output))
        response.headers["Content-Disposition"] = "attachment; filename=masscan_report.txt"
        response.headers["Content-Type"] = "text/plain"
        return response
    elif fmt == 'html':
        html_out = "<html><head><title>Masscan Pro Export Report</title><script src='https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4'></script><style>body { background-color: #0b0f19; color: #e5e7eb; font-family: monospace; }</style></head><body class='p-8 max-w-4xl mx-auto'><h1 class='text-xl font-bold text-rose-500 mb-6 border-b border-slate-800 pb-2'>📋 MASSCAN EXPORTED REPORT</h1><div class='space-y-4'>"
        for ip, ports in scan_state["results"].items():
            html_out += f"<div class='bg-slate-900 border border-slate-800 rounded-lg p-4'><div class='text-sm font-bold text-slate-300 bg-slate-950 px-2 py-1 inline-block rounded border border-slate-800 mb-3'>{ip}</div><div class='flex flex-wrap gap-2'>"
            if ports:
                for p in ports:
                    bg = "bg-rose-950/40 border border-rose-800/60 text-rose-400" if p['state'] == 'open' else "bg-amber-950/40 border border-amber-800/60 text-amber-400"
                    html_out += f'<span class="px-2.5 py-1 rounded text-xs font-bold uppercase border {bg}">{p["port"]}/{p["proto"]} ({p["state"]})</span>'
            else: html_out += '<span class="text-xs text-slate-500 italic">No ports found.</span>'
            html_out += "</div></div>"
        html_out += "</div></body></html>"
        response = make_response(html_out)
        response.headers["Content-Disposition"] = "attachment; filename=masscan_report.html"
        response.headers["Content-Type"] = "text/html"
        return response

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=9998, debug=True)