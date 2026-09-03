#!/usr/bin/env python3
"""
Minimal Flask web UI: drag-and-drop (or click-to-browse) a .eml file,
runs it through the full investigation pipeline, and renders the HTML
report inline. Not meant to replace the CLI for automation -- this is
the "analyst walks up to a browser and drops a suspicious email in" path.

Run:
    python webapp/app.py
    # then open http://localhost:5000
"""
import os
import sys
import uuid

from flask import Flask, render_template, request, redirect, url_for, flash, send_file

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from main import run  # reuses the exact same pipeline as the CLI

BASE_DIR = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORT_DIR = os.path.join(os.path.dirname(BASE_DIR), "reports")
CONFIG_PATH = os.path.join(os.path.dirname(BASE_DIR), "config", "config.yaml")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload cap


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("eml_file")
    if not file or file.filename == "":
        flash("Please choose an .eml file to upload.")
        return redirect(url_for("index"))

    if not file.filename.lower().endswith(".eml"):
        flash("Only .eml files are supported.")
        return redirect(url_for("index"))

    # Unique-ish filename so concurrent analysts don't collide.
    safe_name = f"{uuid.uuid4().hex[:8]}_{os.path.basename(file.filename)}"
    saved_path = os.path.join(UPLOAD_DIR, safe_name)
    file.save(saved_path)

    config_path = CONFIG_PATH if os.path.exists(CONFIG_PATH) else os.path.join(
        os.path.dirname(BASE_DIR), "config", "config.example.yaml"
    )

    try:
        run(saved_path, config_path, REPORT_DIR)
    except Exception as exc:
        flash(f"Analysis failed: {exc}")
        return redirect(url_for("index"))

    base_name = os.path.splitext(os.path.basename(saved_path))[0]
    return redirect(url_for("view_report", name=base_name))


@app.route("/report/<name>")
def view_report(name):
    html_path = os.path.join(REPORT_DIR, f"{name}_report.html")
    if not os.path.exists(html_path):
        flash("Report not found.")
        return redirect(url_for("index"))
    return send_file(html_path)


@app.route("/report/<name>.json")
def view_report_json(name):
    json_path = os.path.join(REPORT_DIR, f"{name}_report.json")
    if not os.path.exists(json_path):
        flash("Report not found.")
        return redirect(url_for("index"))
    return send_file(json_path, mimetype="application/json")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
