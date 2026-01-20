# iot_client.py
import hashlib
import time
import socket
import json
import sys
import random

# --- KONFİGÜRASYON ---
HOST = '127.0.0.1' # Sunucu adresiyle eşleşmeli
PORT = 5507

class IoTDevice:
    def __init__(self, device_id: str, secret_key: str):
        self.device_id = device_id
        self.secret_key = secret_key 

    def generate_response(self, challenge: str) -> str:
        """Hash-Temelli Cevabı (R) üretir."""
        data_to_hash = f"{self.secret_key}|{challenge}"
        response = hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()
        # Küçük bir işlem gecikmesi simülasyonu
        time.sleep(random.uniform(0.001, 0.005)) 
        return response

    def connect_and_authenticate(self):
        """Sunucuya bağlanır ve Challenge-Response protokolünü uygular."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                
                print(f"[{self.device_id}] Sunucuya bağlandı.")

                # 1. Challenge İsteği Gönder (İlk boş istek)
                initial_request = json.dumps({"device_id": self.device_id, "response": None, "challenge": None})
                s.sendall(initial_request.encode('utf-8'))
                
                # 2. Challenge Al
                challenge_raw = s.recv(1024).decode('utf-8')
                challenge_data = json.loads(challenge_raw)
                
                if challenge_data.get('status') == "CHALLENGE":
                    challenge = challenge_data.get('challenge')
                    print(f"[{self.device_id}] Challenge alındı: {challenge[:20]}...")
                else:
                    print(f"[{self.device_id}] HATA: Sunucudan challenge alınamadı. Mesaj: {challenge_data.get('message', 'Bilinmiyor')}")
                    return

                # 3. Cevap Üret
                response_hash = self.generate_response(challenge)
                
                # 4. Cevabı Sunucuya Gönder
                response_request = json.dumps({"device_id": self.device_id, "response": response_hash, "challenge": challenge})
                s.sendall(response_request.encode('utf-8'))
                print(f"[{self.device_id}] Cevap gönderildi: {response_hash[:20]}...")

                # 5. Nihai Sonucu Al
                final_status_raw = s.recv(1024).decode('utf-8')
                final_status = json.loads(final_status_raw)
                
                if final_status.get('status') == "SUCCESS":
                    print(f"[{self.device_id}] ✅ BAŞARILI: {final_status.get('message')}")
                else:
                    print(f"[{self.device_id}] ❌ BAŞARISIZ: {final_status.get('message')}")

        except ConnectionRefusedError:
            print(f"[{self.device_id}] HATA: Sunucu ({HOST}:{PORT}) çalışmıyor veya bağlantıyı reddetti.")
        except Exception as e:
            print(f"[{self.device_id}] Beklenmedik Hata: {e}")

if __name__ == "__main__":
    # Örnek Cihaz Kimlikleri (server.py dosyasındakilerle eşleşmeli)
    
    # Komut satırı argümanı kontrolü
    if len(sys.argv) < 3:
        print("Kullanım: python iot_client.py <DEVICE_ID> <SECRET_KEY>")
        sys.exit(1)

    CLIENT_ID = sys.argv[1]
    CLIENT_KEY = sys.argv[2]
    
    device_client = IoTDevice(CLIENT_ID, CLIENT_KEY)
    device_client.connect_and_authenticate(