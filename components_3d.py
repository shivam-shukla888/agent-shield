"""
AgentShield v2 - Embedded HTML5/JS/Canvas Animation Components (components_3d.py)
Uses streamlit.components.v1.html to render real interactive canvas graphics & animations.
"""

import streamlit as st
import streamlit.components.v1 as components


def render_hero_attack_graph(height: int = 240):
    """
    Renders an HTML5 Canvas node-graph particle animation representing real-time attack probes.
    """
    html_code = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { background: transparent; overflow: hidden; font-family: sans-serif; }
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
                { x: 100, y: 120, label: "PROMPT_LEAK", color: "#4ECDC4", pulse: 0 },
                { x: 300, y: 60,  label: "INSTRUCTION_OVERRIDE", color: "#FF6B35", pulse: 0 },
                { x: 500, y: 150, label: "SSRF_DEFENSE", color: "#4ECDC4", pulse: 0 },
                { x: 700, y: 70,  label: "EXCESSIVE_AGENCY", color: "#E23D5A", pulse: 0 },
                { x: 900, y: 130, label: "PII_DISCLOSURE", color: "#4ECDC4", pulse: 0 }
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
                    ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
                    ctx.lineWidth = 1.5;
                    ctx.stroke();

                    // Pulse Traveling Particle
                    const t = (Math.sin(time + i) + 1) / 2;
                    const px = n1.x + (n2.x - n1.x) * t;
                    const py = n1.y + (n2.y - n1.y) * t;
                    ctx.beginPath();
                    ctx.arc(px, py, 3, 0, Math.PI * 2);
                    ctx.fillStyle = n1.color;
                    ctx.shadowColor = n1.color;
                    ctx.shadowBlur = 10;
                    ctx.fill();
                    ctx.shadowBlur = 0;
                }

                // Draw Nodes
                nodes.forEach((n, idx) => {
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, 8, 0, Math.PI * 2);
                    ctx.fillStyle = n.color;
                    ctx.shadowColor = n.color;
                    ctx.shadowBlur = 15;
                    ctx.fill();
                    ctx.shadowBlur = 0;

                    // Label
                    ctx.fillStyle = "#94A3B8";
                    ctx.font = "11px 'Courier New', monospace";
                    ctx.fillText(n.label, n.x - 40, n.y + 22);
                });

                requestAnimationFrame(animate);
            }
            animate();
        </script>
    </body>
    </html>
    """
    components.html(html_code, height=height, scrolling=False)


def render_radar_sweep(height: int = 220):
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
                background: #0B0D12; 
                display: flex; 
                align-items: center; 
                justify-content: center; 
                height: 100vh;
                font-family: monospace;
            }
            .radar-box {
                position: relative;
                width: 180px;
                height: 180px;
                border-radius: 50%;
                border: 2px solid rgba(78, 205, 196, 0.3);
                background: radial-gradient(circle, rgba(78, 205, 196, 0.05) 0%, transparent 70%);
                overflow: hidden;
            }
            .radar-ring {
                position: absolute;
                top: 50%; left: 50%;
                transform: translate(-50%, -50%);
                border-radius: 50%;
                border: 1px dashed rgba(255, 255, 255, 0.1);
            }
            .r1 { width: 120px; height: 120px; }
            .r2 { width: 60px; height: 60px; }

            .sweep {
                position: absolute;
                top: 0; left: 0; width: 100%; height: 100%;
                border-radius: 50%;
                background: conic-gradient(from 0deg, rgba(226, 61, 90, 0.4) 0deg, transparent 60deg);
                animation: spin 2s linear infinite;
            }

            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }

            .label {
                position: absolute;
                bottom: 10px;
                color: #4ECDC4;
                font-size: 11px;
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
    Renders an animated SVG radial gauge color-shifting from Safe Teal to Crimson.
    """
    pct = max(0, min(100, score))
    color = "#4ECDC4" if pct < 30 else "#FF6B35" if pct < 70 else "#E23D5A"
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
                font-family: 'Sora', sans-serif;
            }}
            .gauge-svg {{
                width: 140px;
                height: 140px;
            }}
            .gauge-bg {{
                fill: none;
                stroke: rgba(255, 255, 255, 0.08);
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
                filter: drop-shadow(0px 0px 8px {color});
            }}
            .gauge-num {{
                fill: #EDEDED;
                font-size: 26px;
                font-weight: 800;
                text-anchor: middle;
                dominant-baseline: central;
            }}
            .gauge-title {{
                color: #94A3B8;
                font-size: 11px;
                margin-top: 6px;
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
        <div class="gauge-title">Risk Index</div>
    </body>
    </html>
    """
    components.html(html_code, height=height, scrolling=False)
