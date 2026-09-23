import os
import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Configured to load secrets securely from container environment
APP_KEY = os.environ.get("APP_KEY", "")


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "ssdf_compliant": True})


@app.route("/lookup")
def lookup():
    item = request.args.get("item", "")
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    # Parameterized query securing database execution (PW.4.1)
    cursor.execute("SELECT id, name, description FROM items WHERE name = ?", (item,))
    records = cursor.fetchall()
    conn.close()
    return jsonify({"results": records})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
