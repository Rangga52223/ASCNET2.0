import pyshark
import websocket
import json
import yaml
import time
import numpy as np

def read_config_yaml(filepath):
    with open(filepath, 'r') as file:
        return yaml.safe_load(file)

def analyze_packet(packet, ws, excluded_ports):
    try:
        dest_port = int(packet[packet.transport_layer].dstport)

        if dest_port in excluded_ports:
            return

        features = {
            "Fwd Packet Length Max": int(packet.length) if hasattr(packet, 'length') else 0,
            "Init_Win_bytes_forward": int(packet.tcp.window_size_value) if hasattr(packet, 'tcp') else 0,
            "Fwd Packet Length Mean": float(packet.length) if hasattr(packet, 'length') else 0,
            "Avg Fwd Segment Size": float(packet.length) if hasattr(packet, 'length') else 0,
            "Subflow Fwd Bytes": int(packet.length) if hasattr(packet, 'length') else 0,
            "Subflow Fwd Packets": 1 if hasattr(packet, 'tcp') else 0,
            "Destination Port": dest_port,
            "Bwd Packet Length Min": int(packet.length) if hasattr(packet, 'length') else 0,
            "act_data_pkt_fwd": 1 if hasattr(packet, 'tcp') else 0,
            "Total Length of Fwd Packets": int(packet.length) if hasattr(packet, 'length') else 0
        }

        print("Sending raw data:", features)

        try:
            ws.send(json.dumps(features))
        except websocket.WebSocketException as e:
            print(f"WebSocket error: {e}")

    except AttributeError:
        pass

def start_realtime_scanning(config):
    ws_url = f"ws://{config['websocket_host']}:{config['websocket_port']}"
    excluded_ports = config.get('excluded_ports', [])
    connected = False

    while not connected:
        try:
            ws = websocket.WebSocket()
            ws.connect(ws_url)
            connected = True
            print("Connected to AI server")

            capture = pyshark.LiveCapture(interface=config['network_interface'])
            print("Starting real-time network scanning...")

            for packet in capture.sniff_continuously():
                analyze_packet(packet, ws, excluded_ports)

        except websocket.WebSocketException as e:
            print(f"WebSocket connection error: {e}")
            time.sleep(5)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            ws.close()

if __name__ == "__main__":
    config = read_config_yaml('config.yaml')
    start_realtime_scanning(config)