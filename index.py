from flask import Flask, render_template, jsonify, request

app = Flask(__name__, template_folder="../templates")

@app.route("/")
def home():
    return render_template("index.html")

# 🔌 SUNUCU / PLC / MODBUS İÇİN API (şimdilik mock)
@app.route("/api/status")
def status():
    return jsonify({
        "system": "online",
        "mode": "normal",
        "connection": "ok"
    })

# 🚨 İLERİDE MODBUS WRITE / SOAR BUTONU
@app.route("/api/control", methods=["POST"])
def control():
    data = request.json
    action = data.get("action")

    # burada ileride modbus write olacak
    print("ACTION:", action)

    return jsonify({"result": "ok", "action": action})


# ⚠️ Vercel için zorunlu
def handler(environ, start_response):
    return app(environ, start_response)
