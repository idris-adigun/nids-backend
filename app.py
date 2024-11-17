from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/traffic', methods=['GET'])
def get_traffic():
    # Replace with real traffic data
    return jsonify([
        {"src": "192.168.1.1", "dst": "8.8.8.8", "protocol": "TCP", "alert": False},
        {"src": "192.168.1.2", "dst": "8.8.4.4", "protocol": "ICMP", "alert": True},
    ])
    

    

if __name__ == '__main__':
    app.run(debug=True)