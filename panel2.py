from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

# 🔧 İLERİDE SUNUCU / PLC / MODBUS İÇİN
@app.route("/api/status")
def status():
    return jsonify({
        "system": "traffic-light",
        "status": "online"
    })

# 🔧 IŞIK DURUMU SUNUCUYA GİDECEK YER
@app.route("/api/light", methods=["POST"])
def set_light():
    data = request.json
    color = data.get("color")
    duration = data.get("duration")

    # burada ileride MODBUS WRITE olacak
    print(f"[SERVER] {color} ışığı {duration}s")

    return jsonify({"ok": True})

# ⚠️ Vercel için GEREKLİ
app = app
