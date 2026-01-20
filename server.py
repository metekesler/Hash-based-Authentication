# server.py
import hashlib
import time
import random
import string
import json
import socket
import threading

# --- KONFİGÜRASYON ---
HOST = '127.0.0.1' # Localhost
PORT = 5507       # İletişim portu
BUFFER_SIZE = 1024

class Node:
    def __init__(self):
        # Kayıtlı Cihazlar: {Device_ID: Secret_Key}
        self.known_secrets = {
            "Klima": "Anahtar_Klima",
            "Termostat": "Anahtar_Termostat",
        }

    def create_genesis_block(self):
        genesis_block = {'index': 0, 'timestamp': time.time(), 'data': 'Genesis', 'hash': self.calculate_hash('Genesis')}
        self.chain.append(genesis_block)

    def get_challenge(self) -> str:
        """Tekrar oynatma saldırılarını önlemek için rastgele Meydan Okuma üretir."""
        nonce = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
        return f"{nonce}:{time.time()}"

    def calculate_expected_response(self, challenge: str, device_id: str) -> str:
        """Düğümün kendi tarafında beklenen cevabı hesaplar."""
        secret = self.known_secrets.get(device_id)
        if not secret:
            return None
        data_to_hash = f"{secret}|{challenge}"
        return hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()

    def calculate_hash(self, data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

# --- SUNUCU İŞLEMLERİ ---
node = Node()

def handle_client(conn, addr):
    try:
        print(f"\n[BAĞLANTI] {addr} bağlandı.")
        
        # 1. Cihaz ID'sini Al
        request_raw = conn.recv(BUFFER_SIZE).decode('utf-8')
        request = json.loads(request_raw)
        
        device_id = request.get('device_id')
        received_response = request.get('response')
        challenge = request.get('challenge')
        
        if not device_id or device_id not in node.known_secrets:
            conn.sendall(json.dumps({"status": "REJECTED", "message": "Bilinmeyen ID."}).encode('utf-8'))
            return

        if not received_response:
            # İlk istek : Challenge Gönder
            challenge_value = node.get_challenge()
            conn.sendall(json.dumps({"status": "CHALLENGE", "challenge": challenge_value}).encode('utf-8'))
            
            # Cihazın cevabını bekle
            response_raw = conn.recv(BUFFER_SIZE).decode('utf-8')
            response_data = json.loads(response_raw)
            received_response = response_data.get('response')
            challenge = response_data.get('challenge')
            
            if not received_response:
                 conn.sendall(json.dumps({"status": "REJECTED", "message": "Cevap gelmedi."}).encode('utf-8'))
                 return

        # 2. Doğrulama Yap
        expected_response = node.calculate_expected_response(challenge, device_id)

        if expected_response == received_response:
            print(f"✅ GÜVENLİ: {device_id}'nin kimliğini başarıyla doğruladı.")
            conn.sendall(json.dumps({"status": "SUCCESS", "message": "Kimlik Doğrulama Başarılı."}).encode('utf-8'))
        else:
            print(f"❌ BAŞARISIZ: {device_id}'nin kimliğini doğrulayamadı!")
            conn.sendall(json.dumps({"status": "FAILURE", "message": "Kimlik Doğrulama Başarısız."}).encode('utf-8'))

    except Exception as e:
        print(f"[HATA] İstemci {addr} ile iletişimde hata: {e}")
    finally:
        conn.close()

def start_server():
    """Ana sunucu döngüsünü başlatır."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    
    try:
        while True:
            # Bağlantıyı kabul et ve yeni bir iş parçacığı başlat
            conn, addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
    except KeyboardInterrupt:
        print("\nSunucu kapatılıyor...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    print("\n" + "="*50)
    print("SENARYO: KİMLİK DOĞRULAMA")
    print("="*50)

    start_server()
