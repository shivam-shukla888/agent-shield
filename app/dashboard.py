"""
AgentShield Interactive Web Dashboard UI Component
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AgentShield | AI Agent Security Dashboard</title>

    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

    <!-- FontAwesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

    <style>
        :root {
            --bg-primary: #0b0f19;
            --bg-card: rgba(18, 24, 38, 0.75);
            --bg-card-hover: rgba(26, 35, 56, 0.85);
            --border-color: rgba(255, 255, 255, 0.08);
            --border-highlight: rgba(99, 102, 241, 0.3);
            
            --accent-indigo: #6366f1;
            --accent-cyan: #06b6d4;
            --accent-emerald: #10b981;
            --accent-amber: #f59e0b;
            --accent-rose: #f43f5e;
            
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;

            --font-main: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-primary);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.12) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(6, 182, 212, 0.1) 0px, transparent 50%),
                radial-gradient(at 50% 50%, rgba(16, 185, 129, 0.05) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-primary);
            font-family: var(--font-main);
            min-height: 100vh;
            line-height: 1.6;
        }

        /* Top Navigation Header */
        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.25rem 2.5rem;
            background: rgba(11, 15, 25, 0.8);
            backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border-color);
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 0.85rem;
            text-decoration: none;
        }

        .brand-logo {
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, var(--accent-indigo), var(--accent-cyan));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.3rem;
            color: white;
            box-shadow: 0 0 20px rgba(99, 102, 241, 0.4);
        }

        .brand-title {
            font-size: 1.4rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            background: linear-gradient(to right, #ffffff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-badge {
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            padding: 0.2rem 0.6rem;
            border-radius: 20px;
            background: rgba(99, 102, 241, 0.15);
            color: var(--accent-cyan);
            border: 1px solid rgba(6, 182, 212, 0.3);
        }

        .nav-actions {
            display: flex;
            align-items: center;
            gap: 1.25rem;
        }

        .status-pill {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--accent-emerald);
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.25);
            padding: 0.4rem 0.9rem;
            border-radius: 30px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background-color: var(--accent-emerald);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--accent-emerald);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        .btn-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            transition: all 0.2s ease;
        }

        .btn-link:hover {
            color: white;
            background: rgba(255, 255, 255, 0.05);
        }

        /* Container & Layout */
        .container {
            max-width: 1320px;
            margin: 0 auto;
            padding: 2rem 1.5rem 4rem;
        }

        /* Hero Banner */
        .hero {
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            margin-bottom: 2rem;
        }

        .hero-text h1 {
            font-size: 2.2rem;
            font-weight: 700;
            letter-spacing: -0.03em;
            margin-bottom: 0.3rem;
        }

        .hero-text p {
            color: var(--text-secondary);
            font-size: 1rem;
        }

        /* Stat Cards Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2.5rem;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(12px);
            border-radius: 16px;
            padding: 1.5rem;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            border-color: var(--border-highlight);
            background: var(--bg-card-hover);
        }

        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .stat-title {
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .stat-icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
        }

        .icon-indigo { background: rgba(99, 102, 241, 0.15); color: var(--accent-indigo); }
        .icon-rose { background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); }
        .icon-cyan { background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan); }
        .icon-emerald { background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }

        .stat-subtitle {
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-top: 0.3rem;
        }

        /* Dashboard Grid Layout */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 380px 1fr;
            gap: 1.5rem;
        }

        @media (max-width: 992px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Glassmorphism Panel */
        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            backdrop-filter: blur(12px);
            border-radius: 16px;
            padding: 1.75rem;
        }

        .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        .panel-title {
            font-size: 1.15rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }

        .panel-title i {
            color: var(--accent-indigo);
        }

        /* Form Controls */
        .form-group {
            margin-bottom: 1.25rem;
        }

        .form-label {
            display: block;
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }

        .form-input, .form-select {
            width: 100%;
            background: rgba(11, 15, 25, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 0.75rem 1rem;
            color: var(--text-primary);
            font-family: var(--font-main);
            font-size: 0.9rem;
            transition: all 0.2s ease;
        }

        .form-input:focus, .form-select:focus {
            outline: none;
            border-color: var(--accent-indigo);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
            background: rgba(11, 15, 25, 0.8);
        }

        /* Checkbox Group */
        .probe-selector {
            display: flex;
            flex-direction: column;
            gap: 0.6rem;
            max-height: 200px;
            overflow-y: auto;
            padding-right: 0.5rem;
        }

        .probe-option {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            padding: 0.6rem 0.85rem;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .probe-option:hover {
            border-color: rgba(99, 102, 241, 0.4);
            background: rgba(99, 102, 241, 0.05);
        }

        .probe-label {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .probe-checkbox {
            accent-color: var(--accent-indigo);
            width: 16px;
            height: 16px;
        }

        .probe-tag {
            font-family: var(--font-mono);
            font-size: 0.7rem;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.06);
            color: var(--text-muted);
        }

        /* Action Button */
        .btn-submit {
            width: 100%;
            background: linear-gradient(135deg, var(--accent-indigo), #4f46e5);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 0.85rem 1.5rem;
            font-size: 0.95rem;
            font-weight: 600;
            font-family: var(--font-main);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.6rem;
            transition: all 0.2s ease;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.35);
            margin-top: 1.5rem;
        }

        .btn-submit:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.5);
            background: linear-gradient(135deg, #6366f1, #4338ca);
        }

        .btn-submit:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        /* Table Styling */
        .table-responsive {
            width: 100%;
            overflow-x: auto;
        }

        .scan-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }

        .scan-table th {
            text-align: left;
            padding: 0.85rem 1rem;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border-color);
        }

        .scan-table td {
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            vertical-align: middle;
        }

        .scan-table tbody tr {
            transition: background-color 0.2s ease;
        }

        .scan-table tbody tr:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }

        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.25rem 0.65rem;
            border-radius: 20px;
            font-family: var(--font-mono);
        }

        .badge-completed { background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-running { background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-failed { background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); border: 1px solid rgba(244, 63, 94, 0.3); }

        .badge-risk-critical { background: rgba(244, 63, 94, 0.2); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.4); }
        .badge-risk-high { background: rgba(245, 158, 11, 0.2); color: #fde68a; border: 1px solid rgba(245, 158, 11, 0.4); }
        .badge-risk-medium { background: rgba(6, 182, 212, 0.2); color: #a5f3fc; border: 1px solid rgba(6, 182, 212, 0.4); }
        .badge-risk-low { background: rgba(16, 185, 129, 0.2); color: #a7f3d0; border: 1px solid rgba(16, 185, 129, 0.4); }

        .scan-id {
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: var(--accent-cyan);
            font-weight: 500;
        }

        /* Action Buttons in Table */
        .action-group {
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }

        .btn-action {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 0.4rem 0.7rem;
            border-radius: 6px;
            font-size: 0.78rem;
            font-weight: 500;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            transition: all 0.2s ease;
            cursor: pointer;
        }

        .btn-action:hover {
            color: white;
            background: rgba(99, 102, 241, 0.2);
            border-color: rgba(99, 102, 241, 0.4);
        }

        /* Empty State */
        .empty-state {
            padding: 3rem 1rem;
            text-align: center;
            color: var(--text-muted);
        }

        .empty-state i {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            color: rgba(255, 255, 255, 0.15);
        }

        /* Modal Drawer */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(8px);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
        }

        .modal-overlay.active {
            opacity: 1;
            pointer-events: auto;
        }

        .modal-container {
            background: #0f172a;
            border: 1px solid var(--border-highlight);
            width: 90%;
            max-width: 900px;
            max-height: 85vh;
            border-radius: 20px;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
        }

        .modal-header {
            padding: 1.25rem 1.75rem;
            background: rgba(15, 23, 42, 0.9);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-close {
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 1.2rem;
            cursor: pointer;
            transition: color 0.2s;
        }

        .modal-close:hover { color: white; }

        .modal-body {
            padding: 1.5rem 1.75rem;
            overflow-y: auto;
            flex: 1;
        }

        pre.code-block {
            background: #090d16;
            padding: 1rem;
            border-radius: 8px;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            color: #38bdf8;
            overflow-x: auto;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
    </style>
</head>
<body>

    <!-- Top Navigation Header -->
    <nav class="navbar">
        <a href="/dashboard" class="brand">
            <div class="brand-logo">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div>
                <div class="brand-title">AgentShield</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">AI Agent Security Platform</div>
            </div>
            <span class="brand-badge">v1.0</span>
        </a>

        <div class="nav-actions">
            <div class="status-pill">
                <span class="status-dot"></span>
                <span>System Operational</span>
            </div>
            <a href="/docs" target="_blank" class="btn-link">
                <i class="fa-solid fa-book-open"></i> API Specs
            </a>
            <a href="/health" target="_blank" class="btn-link">
                <i class="fa-solid fa-heart-pulse"></i> Health
            </a>
        </div>
    </nav>

    <!-- Main Content Container -->
    <div class="container">
        
        <!-- Hero Header -->
        <div class="hero">
            <div class="hero-text">
                <h1>Security Audit Dashboard</h1>
                <p>Monitor vulnerabilities, execute prompt injection probes, and audit AI agent risk posture.</p>
            </div>
            <div>
                <button onclick="loadScans()" class="btn-action" style="padding: 0.6rem 1rem; font-size: 0.85rem;">
                    <i class="fa-solid fa-arrows-rotate"></i> Refresh Data
                </button>
            </div>
        </div>

        <!-- Metrics Cards Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-title">Total Scans</span>
                    <div class="stat-icon icon-indigo"><i class="fa-solid fa-crosshairs"></i></div>
                </div>
                <div class="stat-value" id="stat-total-scans">0</div>
                <div class="stat-subtitle">Executed security audits</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-title">Vulnerabilities Detected</span>
                    <div class="stat-icon icon-rose"><i class="fa-solid fa-bug"></i></div>
                </div>
                <div class="stat-value" id="stat-vulns">0</div>
                <div class="stat-subtitle">Prompt leaks & safety bypasses</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-title">Probe Suite Count</span>
                    <div class="stat-icon icon-cyan"><i class="fa-solid fa-cubes-stacked"></i></div>
                </div>
                <div class="stat-value">5</div>
                <div class="stat-subtitle">Deterministic & LLM Evaluators</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-title">Average Latency</span>
                    <div class="stat-icon icon-emerald"><i class="fa-solid fa-bolt"></i></div>
                </div>
                <div class="stat-value" id="stat-latency">&lt; 15ms</div>
                <div class="stat-subtitle">Async pipeline processing</div>
            </div>
        </div>

        <!-- Dashboard Main Grid -->
        <div class="dashboard-grid">
            
            <!-- Left Column: Submit New Scan -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <i class="fa-solid fa-play"></i> Launch Security Audit
                    </div>
                </div>

                <form id="scan-form" onsubmit="handleScanSubmit(event)">
                    <div class="form-group">
                        <label class="form-label" for="target_name">Target Agent Name</label>
                        <input type="text" id="target_name" class="form-input" placeholder="e.g. Support-Bot-v2" required value="Customer Support Bot">
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="endpoint">Target API Endpoint</label>
                        <input type="url" id="endpoint" class="form-input" placeholder="http://localhost:8000/chat" required value="http://localhost:8000/chat">
                    </div>

                    <div class="form-group">
                        <label class="form-label">Select Security Probes</label>
                        <div class="probe-selector">
                            <label class="probe-option">
                                <span class="probe-label">
                                    <input type="checkbox" class="probe-checkbox" value="PROMPT_LEAK_001" checked>
                                    Prompt Leakage
                                </span>
                                <span class="probe-tag">LEAK_001</span>
                            </label>

                            <label class="probe-option">
                                <span class="probe-label">
                                    <input type="checkbox" class="probe-checkbox" value="INSTRUCTION_OVERRIDE_001" checked>
                                    Instruction Override
                                </span>
                                <span class="probe-tag">OVERRIDE_001</span>
                            </label>

                            <label class="probe-option">
                                <span class="probe-label">
                                    <input type="checkbox" class="probe-checkbox" value="SSRF_VALIDATION_001" checked>
                                    SSRF Pipeline Protection
                                </span>
                                <span class="probe-tag">SSRF_001</span>
                            </label>

                            <label class="probe-option">
                                <span class="probe-label">
                                    <input type="checkbox" class="probe-checkbox" value="SYSTEM_PROMPT_EXTRACTION_001" checked>
                                    System Prompt Extract
                                </span>
                                <span class="probe-tag">SYS_EXT_001</span>
                            </label>

                            <label class="probe-option">
                                <span class="probe-label">
                                    <input type="checkbox" class="probe-checkbox" value="DATA_EXFILTRATION_001" checked>
                                    Data Exfiltration
                                </span>
                                <span class="probe-tag">EXFIL_001</span>
                            </label>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="impact">Impact Level</label>
                        <select id="impact" class="form-select">
                            <option value="medium" selected>Medium Impact</option>
                            <option value="high">High Impact</option>
                            <option value="critical">Critical Impact</option>
                            <option value="low">Low Impact</option>
                        </select>
                    </div>

                    <button type="submit" class="btn-submit" id="submit-btn">
                        <i class="fa-solid fa-shield-virus"></i> Execute Security Scan
                    </button>
                </form>
            </div>

            <!-- Right Column: Scan History Table -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <i class="fa-solid fa-list-check"></i> Security Audit Executions
                    </div>
                    <span class="probe-tag" id="scan-count-tag">0 Scans</span>
                </div>

                <div class="table-responsive">
                    <table class="scan-table">
                        <thead>
                            <tr>
                                <th>Scan ID</th>
                                <th>Target</th>
                                <th>Status</th>
                                <th>Risk Score</th>
                                <th>Findings</th>
                                <th>Reports</th>
                            </tr>
                        </thead>
                        <tbody id="scan-table-body">
                            <tr>
                                <td colspan="6">
                                    <div class="empty-state">
                                        <i class="fa-solid fa-spinner fa-spin"></i>
                                        <p>Loading security audit history...</p>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

        </div>

    </div>

    <!-- Scan Detail Modal Drawer -->
    <div class="modal-overlay" id="scan-modal">
        <div class="modal-container">
            <div class="modal-header">
                <h3 id="modal-title" style="font-size: 1.1rem; font-weight: 600;">Scan Details</h3>
                <button class="modal-close" onclick="closeModal()"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div class="modal-body" id="modal-body">
                <!-- Dynamically populated -->
            </div>
        </div>
    </div>

    <!-- JavaScript Logic -->
    <script>
        const API_KEY = "changeme-generate-a-real-key"; // Default development master key

        async function fetchAPI(url, options = {}) {
            const defaultHeaders = {
                "X-API-Key": API_KEY,
                "Content-Type": "application/json"
            };
            options.headers = { ...defaultHeaders, ...(options.headers || {}) };
            const resp = await fetch(url, options);
            if (!resp.ok) {
                const errData = await resp.json().catch(() => ({ detail: "API Request Failed" }));
                throw new Error(errData.detail || `HTTP ${resp.status}`);
            }
            return resp;
        }

        async function loadScans() {
            const tbody = document.getElementById("scan-table-body");
            try {
                const resp = await fetchAPI("/api/v1/scans");
                const scans = await resp.json();
                
                document.getElementById("stat-total-scans").innerText = scans.length;
                document.getElementById("scan-count-tag").innerText = `${scans.length} Scans`;

                let totalVulns = 0;

                if (scans.length === 0) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="6">
                                <div class="empty-state">
                                    <i class="fa-solid fa-shield"></i>
                                    <p>No security scans executed yet. Launch a scan using the panel on the left.</p>
                                </div>
                            </td>
                        </tr>`;
                    return;
                }

                tbody.innerHTML = scans.map(scan => {
                    const vulnsCount = scan.findings ? scan.findings.length : 0;
                    totalVulns += vulnsCount;

                    const statusClass = scan.status === "COMPLETED" ? "badge-completed" : 
                                       scan.status === "RUNNING" ? "badge-running" : "badge-failed";

                    let riskBadge = '<span class="badge badge-risk-low">LOW</span>';
                    const score = scan.risk_score || 0;
                    if (score >= 80) riskBadge = `<span class="badge badge-risk-critical">CRITICAL (${score})</span>`;
                    else if (score >= 60) riskBadge = `<span class="badge badge-risk-high">HIGH (${score})</span>`;
                    else if (score >= 30) riskBadge = `<span class="badge badge-risk-medium">MEDIUM (${score})</span>`;

                    return `
                        <tr>
                            <td><span class="scan-id">${scan.scan_id.substring(0, 16)}...</span></td>
                            <td><strong>${escapeHtml(scan.target ? scan.target.target_name : "Target")}</strong></td>
                            <td><span class="badge ${statusClass}">${scan.status}</span></td>
                            <td>${riskBadge}</td>
                            <td><strong>${vulnsCount}</strong> vulnerabilities</td>
                            <td>
                                <div class="action-group">
                                    <button onclick="viewScanDetails('${scan.scan_id}')" class="btn-action" title="View Payload Details">
                                        <i class="fa-solid fa-eye"></i> Details
                                    </button>
                                    <a href="/api/v1/scans/${scan.scan_id}/report?format=html" target="_blank" class="btn-action" title="Open HTML Security Report">
                                        <i class="fa-solid fa-file-code"></i> HTML
                                    </a>
                                    <a href="/api/v1/scans/${scan.scan_id}/report?format=pdf" class="btn-action" title="Download PDF Report">
                                        <i class="fa-solid fa-file-pdf"></i> PDF
                                    </a>
                                </div>
                            </td>
                        </tr>`;
                }).join("");

                document.getElementById("stat-vulns").innerText = totalVulns;

            } catch (err) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6">
                            <div class="empty-state" style="color: var(--accent-rose);">
                                <i class="fa-solid fa-circle-exclamation"></i>
                                <p>Failed to load scans: ${escapeHtml(err.message)}</p>
                            </div>
                        </td>
                    </tr>`;
            }
        }

        async function handleScanSubmit(event) {
            event.preventDefault();
            const btn = document.getElementById("submit-btn");
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Executing Audit...`;

            const targetName = document.getElementById("target_name").value;
            const endpoint = document.getElementById("endpoint").value;
            const impact = document.getElementById("impact").value;

            const selectedProbes = Array.from(document.querySelectorAll('.probe-checkbox:checked'))
                                       .map(cb => cb.value);

            const payload = {
                target: {
                    target_name: targetName,
                    endpoint: endpoint
                },
                probes: {
                    probe_ids: selectedProbes.length > 0 ? selectedProbes : ["PROMPT_LEAK_001"]
                },
                risk_context: {
                    impact: impact,
                    exploitability: "medium",
                    blast_radius: "medium",
                    asset_sensitivity: "internal",
                    tool_privilege: "read"
                }
            };

            try {
                const resp = await fetchAPI("/api/v1/scans", {
                    method: "POST",
                    body: JSON.stringify(payload)
                });
                const scan = await resp.json();
                
                // Refresh list after brief delay for async execution
                setTimeout(loadScans, 800);
            } catch (err) {
                alert("Scan Submission Failed: " + err.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-shield-virus"></i> Execute Security Scan`;
            }
        }

        async function viewScanDetails(scanId) {
            const modal = document.getElementById("scan-modal");
            const modalBody = document.getElementById("modal-body");
            document.getElementById("modal-title").innerText = `Scan Inspection [${scanId}]`;
            
            modalBody.innerHTML = `<div style="text-align: center; padding: 2rem;"><i class="fa-solid fa-spinner fa-spin fa-2x"></i></div>`;
            modal.classList.add("active");

            try {
                const resp = await fetchAPI(`/api/v1/scans/${scanId}`);
                const data = await resp.json();
                modalBody.innerHTML = `
                    <h4 style="margin-bottom: 0.5rem; color: var(--accent-cyan);">Target Specifications</h4>
                    <p style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 1rem;">
                        <strong>Name:</strong> ${escapeHtml(data.target.target_name)} | 
                        <strong>Endpoint:</strong> <code>${escapeHtml(data.target.endpoint)}</code>
                    </p>
                    
                    <h4 style="margin-bottom: 0.5rem; color: var(--accent-rose);">Security Findings (${data.findings ? data.findings.length : 0})</h4>
                    ${data.findings && data.findings.length > 0 ? `
                        <div style="margin-bottom: 1.5rem;">
                            ${data.findings.map(f => `
                                <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); padding: 0.85rem; border-radius: 8px; margin-bottom: 0.5rem;">
                                    <div style="display: flex; justify-content: space-between; font-weight: 600; margin-bottom: 0.3rem;">
                                        <span style="color: var(--accent-rose);">${escapeHtml(f.title || f.finding_id)}</span>
                                        <span class="badge badge-risk-critical">${escapeHtml(f.severity)}</span>
                                    </div>
                                    <div style="font-size: 0.85rem; color: var(--text-secondary);">${escapeHtml(f.description || '')}</div>
                                </div>
                            `).join('')}
                        </div>
                    ` : '<p style="color: var(--accent-emerald); font-size: 0.9rem; margin-bottom: 1.5rem;">No security vulnerabilities detected during this scan execution.</p>'}

                    <h4 style="margin-bottom: 0.5rem; color: var(--text-secondary);">Raw JSON Response DTO</h4>
                    <pre class="code-block">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
                `;
            } catch (err) {
                modalBody.innerHTML = `<p style="color: var(--accent-rose);">Failed to retrieve scan: ${escapeHtml(err.message)}</p>`;
            }
        }

        function closeModal() {
            document.getElementById("scan-modal").classList.remove("active");
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // Initial load on page ready
        document.addEventListener("DOMContentLoaded", loadScans);
    </script>
</body>
</html>
"""
