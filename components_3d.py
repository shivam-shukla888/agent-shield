"""
AgentShield v2 - Embedded HTML5/JS/Canvas Animation Components (components_3d.py)
Uses streamlit.components.v1.html to render real interactive canvas graphics & animations.
Light Theme Design System Integration
"""

import streamlit.components.v1 as components



def render_hero_attack_graph(height: int = 140):
    """
    Renders an HTML5 Canvas node-graph particle animation representing real-time attack probes.
    """
    html_code = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { background: transparent; overflow: hidden; font-family: 'Inter', sans-serif; }
            canvas { display: block; width: 100%; height: 100%; }
        </style>
    </head>
    <body>
        <canvas id="attackCanvas"></canvas>
        <script>
            const canvas = document.getElementById('attackCanvas');
            const ctx = canvas.getContext('2d');
            
            function resize() {
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
            }
            window.addEventListener('resize', resize);
            resize();

            const nodes = [
                { x: 100, y: 70, label: "PROMPT_LEAK_001", color: "#006c4a", pulse: 0 },
                { x: 300, y: 35,  label: "INSTRUCTION_OVERRIDE", color: "#d97706", pulse: 0 },
                { x: 500, y: 85, label: "SSRF_DEFENSE_GATEWAY", color: "#2563eb", pulse: 0 },
                { x: 700, y: 40,  label: "EXCESSIVE_AGENCY", color: "#d52022", pulse: 0 },
                { x: 900, y: 75, label: "PII_CREDENTIAL_CHECK", color: "#006c4a", pulse: 0 }
            ];

            let time = 0;
            function animate() {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                time += 0.03;

                // Draw Edges
                for (let i = 0; i < nodes.length - 1; i++) {
                    const n1 = nodes[i];
                    const n2 = nodes[i + 1];
                    ctx.beginPath();
                    ctx.moveTo(n1.x, n1.y);
                    ctx.lineTo(n2.x, n2.y);
                    ctx.strokeStyle = "rgba(195, 198, 215, 0.4)";
                    ctx.lineWidth = 1.5;
                    ctx.stroke();

                    // Pulse Traveling Particle
                    const t = (Math.sin(time + i) + 1) / 2;
                    const px = n1.x + (n2.x - n1.x) * t;
                    const py = n1.y + (n2.y - n1.y) * t;
                    ctx.beginPath();
                    ctx.arc(px, py, 4, 0, Math.PI * 2);
                    ctx.fillStyle = n1.color;
                    ctx.shadowColor = n1.color;
                    ctx.shadowBlur = 6;
                    ctx.fill();
                    ctx.shadowBlur = 0;
                }

                // Draw Nodes
                nodes.forEach((n, idx) => {
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, 7, 0, Math.PI * 2);
                    ctx.fillStyle = n.color;
                    ctx.shadowColor = n.color;
                    ctx.shadowBlur = 8;
                    ctx.fill();
                    ctx.shadowBlur = 0;

                    // Label
                    ctx.fillStyle = "#434655";
                    ctx.font = "600 11px 'JetBrains Mono', monospace";
                    ctx.fillText(n.label, n.x - 45, n.y + 22);
                });

                requestAnimationFrame(animate);
            }
            animate();
        </script>
    </body>
    </html>
    """
    components.html(html_code, height=height, scrolling=False)


def render_radar_sweep(height: int = 180):
    """
    Renders an animated SVG/CSS Radar Scanner representing active scan execution.
    """
    html_code = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                background: transparent; 
                display: flex; 
                align-items: center; 
                justify-content: center; 
                height: 100vh;
                font-family: 'JetBrains Mono', monospace;
            }
            .radar-box {
                position: relative;
                width: 140px;
                height: 140px;
                border-radius: 50%;
                border: 2px solid rgba(37, 99, 235, 0.3);
                background: radial-gradient(circle, rgba(37, 99, 235, 0.06) 0%, transparent 70%);
                overflow: hidden;
            }
            .radar-ring {
                position: absolute;
                top: 50%; left: 50%;
                transform: translate(-50%, -50%);
                border-radius: 50%;
                border: 1px dashed rgba(19, 27, 46, 0.15);
            }
            .r1 { width: 95px; height: 95px; }
            .r2 { width: 45px; height: 45px; }

            .sweep {
                position: absolute;
                top: 0; left: 0; width: 100%; height: 100%;
                border-radius: 50%;
                background: conic-gradient(from 0deg, rgba(37, 99, 235, 0.4) 0deg, transparent 60deg);
                animation: spin 1.8s linear infinite;
            }

            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }

            .label {
                position: absolute;
                bottom: 8px;
                color: #004ac6;
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 1px;
            }
        </style>
    </head>
    <body>
        <div class="radar-box">
            <div class="radar-ring r1"></div>
            <div class="radar-ring r2"></div>
            <div class="sweep"></div>
        </div>
    </body>
    </html>
    """
    components.html(html_code, height=height, scrolling=False)


def render_risk_score_gauge(score: int, height: int = 180):
    """
    Renders an animated SVG radial gauge color-shifting from Emerald to Crimson.
    """
    pct = max(0, min(100, score))
    color = "#006c4a" if pct < 30 else "#d97706" if pct < 70 else "#d52022"
    dash_offset = 283 - (283 * pct / 100)

    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                background: transparent;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                height: 100vh;
                font-family: 'Plus Jakarta Sans', sans-serif;
            }}
            .gauge-svg {{
                width: 130px;
                height: 130px;
            }}
            .gauge-bg {{
                fill: none;
                stroke: #e2e7ff;
                stroke-width: 10;
            }}
            .gauge-fill {{
                fill: none;
                stroke: {color};
                stroke-width: 10;
                stroke-linecap: round;
                stroke-dasharray: 283;
                stroke-dashoffset: {dash_offset};
                transition: stroke-dashoffset 1s ease-in-out;
                filter: drop-shadow(0px 1px 4px {color});
            }}
            .gauge-num {{
                fill: #131b2e;
                font-size: 26px;
                font-weight: 800;
                font-family: 'JetBrains Mono', monospace;
                text-anchor: middle;
                dominant-baseline: central;
            }}
            .gauge-title {{
                color: #434655;
                font-size: 11px;
                font-weight: 700;
                margin-top: 4px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
        </style>
    </head>
    <body>
        <svg class="gauge-svg" viewBox="0 0 100 100">
            <circle class="gauge-bg" cx="50" cy="50" r="45" />
            <circle class="gauge-fill" cx="50" cy="50" r="45" transform="rotate(-90 50 50)" />
            <text class="gauge-num" x="50" y="50">{pct}</text>
        </svg>
        <div class="gauge-title">Risk Score Index</div>
    </body>
    </html>
    """
    components.html(html_code, height=height, scrolling=False)

