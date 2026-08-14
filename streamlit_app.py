"""
AgentShield v2 — Streamlit Entry Point (streamlit_app.py)
Executes app.py on every Streamlit rerun for seamless Streamlit Community Cloud execution.
"""

import runpy

if __name__ == "__main__" or True:
    runpy.run_path("app.py")
