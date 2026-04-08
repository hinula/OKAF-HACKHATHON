<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trafik Lambası Kontrol Paneli</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .container {
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            justify-content: center;
            align-items: flex-start;
        }

        .traffic-light {
            background: linear-gradient(145deg, #2c3e50, #1a252f);
            padding: 30px;
            border-radius: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.4);
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .light {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: #333;
            box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
            transition: all 0.3s ease;
            position: relative;
        }

        .light.active {
            box-shadow: 0 0 40px currentColor, inset 0 0 20px rgba(255,255,255,0.3);
            filter: brightness(1.2);
        }

        .red { background: radial-gradient(circle at 30% 30%, #ff4444, #cc0000); }
        .yellow { background: radial-gradient(circle at 30% 30%, #ffdd44, #cc8800); }
        .green { background: radial-gradient(circle at 30% 30%, #44ff44, #00cc00); }

        .control-panel {
            background: white;
            padding: 30px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            min-width: 320px;
            max-width: 400px;
        }

        .control-panel h2 {
            color: #2c3e50;
            margin-bottom: 25px;
            font-size: 24px;
            text-align: center;
        }

        .control-group {
            margin-bottom: 25px;
        }

        .control-group label {
            display: block;
            color: #555;
            margin-bottom: 8px;
            font-weight: 600;
            font-size: 14px;
        }

        .control-group input[type="range"] {
            width: 100%;
            height: 6px;
            border-radius: 5px;
            background: #ddd;
            outline: none;
            -webkit-appearance: none;
        }

        .control-group input[type="range"]::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: #667eea;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .control-group input[type="range"]::-webkit-slider-thumb:hover {
            background: #764ba2;
            transform: scale(1.2);
        }

        .value-display {
            display: flex;
            justify-content: space-between;
            margin-top: 5px;
            font-size: 13px;
            color: #888;
        }

        .value-current {
            font-weight: bold;
            color: #667eea;
        }

        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        button {
            flex: 1;
            padding: 12px 20px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .btn-start {
            background: linear-gradient(135deg, #00c853, #00b248);
            color: white;
        }

        .btn-start:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,200,83,0.4);
        }

        .btn-stop {
            background: linear-gradient(135deg, #ff5252, #e63946);
            color: white;
        }

        .btn-stop:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(255,82,82,0.4);
        }

        .btn-reset {
            background: linear-gradient(135deg, #ffa726, #fb8c00);
            color: white;
        }

        .btn-reset:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(255,167,38,0.4);
        }

        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }

        .status {
            text-align: center;
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            font-weight: 600;
            background: #f5f5f5;
        }

        .status.running {
            background: #e8f5e9;
            color: #2e7d32;
        }

        .status.stopped {
            background: #ffebee;
            color: #c62828;
        }

        .timer {
            text-align: center;
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
            margin: 15px 0;
            font-variant-numeric: tabular-nums;
        }

        .mode-selector {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .mode-btn {
            flex: 1;
            padding: 10px;
            border: 2px solid #ddd;
            background: white;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 14px;
        }

        .mode-btn.active {
            border-color: #667eea;
            background: #667eea;
            color: white;
        }

        @media (max-width: 768px) {
            .container {
                flex-direction: column;
            }
            
            .control-panel {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="traffic-light">
            <div class="light red" id="redLight"></div>
            <div class="light yellow" id="yellowLight"></div>
            <div class="light green" id="greenLight"></div>
        </div>

        <div class="control-panel">
            <h2>🚦 Kontrol Paneli</h2>

            <div class="mode-selector">
                <button class="mode-btn active" onclick="setMode('normal')">Normal</button>
                <button class="mode-btn" onclick="setMode('night')">Gece</button>
                <button class="mode-btn" onclick="setMode('emergency')">Acil</button>
            </div>

            <div class="control-group">
                <label>Kırmızı Işık Süresi</label>
                <input type="range" id="redDuration" min="1" max="20" value="5" step="1" oninput="updateValue('red', this.value)">
                <div class="value-display">
                    <span>Min: 1s</span>
                    <span class="value-current" id="redValue">5 saniye</span>
                    <span>Max: 20s</span>
                </div>
            </div>

            <div class="control-group">
                <label>Sarı Işık Süresi</label>
                <input type="range" id="yellowDuration" min="1" max="10" value="2" step="1" oninput="updateValue('yellow', this.value)">
                <div class="value-display">
                    <span>Min: 1s</span>
                    <span class="value-current" id="yellowValue">2 saniye</span>
                    <span>Max: 10s</span>
                </div>
            </div>

            <div class="control-group">
                <label>Yeşil Işık Süresi</label>
                <input type="range" id="greenDuration" min="1" max="20" value="5" step="1" oninput="updateValue('green', this.value)">
                <div class="value-display">
                    <span>Min: 1s</span>
                    <span class="value-current" id="greenValue">5 saniye</span>
                    <span>Max: 20s</span>
                </div>
            </div>

            <div class="timer" id="timer">--</div>

            <div class="button-group">
                <button class="btn-start" id="startBtn" onclick="startTrafficLight()">Başlat</button>
                <button class="btn-stop" id="stopBtn" onclick="stopTrafficLight()" disabled>Durdur</button>
            </div>

            <button class="btn-reset" onclick="resetTrafficLight()" style="width: 100%; margin-top: 10px;">Sıfırla</button>

            <div class="status stopped" id="status">Duruyor</div>
        </div>
    </div>

    <script>
        let intervalId = null;
        let currentLight = 'red';
        let timeRemaining = 0;
        let isRunning = false;
        let currentMode = 'normal';

        const lights = {
            red: document.getElementById('redLight'),
            yellow: document.getElementById('yellowLight'),
            green: document.getElementById('greenLight')
        };

        const durations = {
            red: 5,
            yellow: 2,
            green: 5
        };

        const modes = {
            normal: { red: 5, yellow: 2, green: 5 },
            night: { red: 2, yellow: 1, green: 8 },
            emergency: { red: 1, yellow: 0.5, green: 1 }
        };

        function setMode(mode) {
            currentMode = mode;
            const modeButtons = document.querySelectorAll('.mode-btn');
            modeButtons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            if (!isRunning) {
                durations.red = modes[mode].red;
                durations.yellow = modes[mode].yellow;
                durations.green = modes[mode].green;

                document.getElementById('redDuration').value = durations.red;
                document.getElementById('yellowDuration').value = durations.yellow;
                document.getElementById('greenDuration').value = durations.green;

                updateValue('red', durations.red);
                updateValue('yellow', durations.yellow);
                updateValue('green', durations.green);
            }
        }

        function updateValue(color, value) {
            durations[color] = parseInt(value);
            document.getElementById(${color}Value).textContent = ${value} saniye;
        }

        function activateLight(color) {
            Object.values(lights).forEach(light => light.classList.remove('active'));
            lights[color].classList.add('active');
            currentLight = color;
        }

        function updateTimer() {
            const minutes = Math.floor(timeRemaining / 60);
            const seconds = timeRemaining % 60;
            document.getElementById('timer').textContent = 
                ${seconds.toString().padStart(2, '0')}s;
            
            if (timeRemaining > 0) {
                timeRemaining--;
            } else {
                nextLight();
            }
        }

        function nextLight() {
            const sequence = ['red', 'yellow', 'green'];
            const currentIndex = sequence.indexOf(currentLight);
            const nextIndex = (currentIndex + 1) % sequence.length;
            const nextColor = sequence[nextIndex];
            
            activateLight(nextColor);
            timeRemaining = durations[nextColor];
        }

        function startTrafficLight() {
            if (isRunning) return;
            
            isRunning = true;
            document.getElementById('startBtn').disabled = true;
            document.getElementById('stopBtn').disabled = false;
            document.getElementById('status').textContent = 'Çalışıyor';
            document.getElementById('status').className = 'status running';
            
            // Disable sliders when running
            document.querySelectorAll('input[type="range"]').forEach(slider => {
                slider.disabled = true;
            });
            
            activateLight('red');
            timeRemaining = durations.red;
            
            intervalId = setInterval(updateTimer, 1000);
        }

        function stopTrafficLight() {
            if (!isRunning) return;
            
            isRunning = false;
            clearInterval(intervalId);
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
            document.getElementById('status').textContent = 'Duruyor';
            document.getElementById('status').className = 'status stopped';
            
            // Enable sliders when stopped
            document.querySelectorAll('input[type="range"]').forEach(slider => {
                slider.disabled = false;
            });
        }

        function resetTrafficLight() {
            stopTrafficLight();
            Object.values(lights).forEach(light => light.classList.remove('active'));
            document.getElementById('timer').textContent = '--';
            timeRemaining = 0;
            currentLight = 'red';
        }

        // Initialize
        updateValue('red', durations.red);
        updateValue('yellow', durations.yellow);
        updateValue('green', durations.green);
    </script>
</body>
</html>
