import threading
import time
import requests
from flask import Flask, json, request, jsonify
from scapy.all import *
import pandas as pd
import numpy as np
import secrets
import hashlib
import hmac
from collections import defaultdict
from sklearn.ensemble import VotingClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, Flatten, Dropout, Input
from sklearn.base import BaseEstimator, ClassifierMixin

app = Flask(__name__)

ENTITY_ID = "capture_engine_1"
SESSION_KEY = None
TRA_URL = "http://localhost:6000"
CLOUD_SERVER_URL = "http://localhost:5000"  

def register_with_tra():
    global SESSION_KEY
    response = requests.post(
        f"{TRA_URL}/register",
        json={"entity_id": ENTITY_ID, "entity_type": "capture_engine"}
    )
    if response.status_code == 201:
        SESSION_KEY = response.json()["session_key"]
        print("Successfully registered with TRA. SKEY:", SESSION_KEY)
    else:
        raise Exception("TRA registration failed")

def generate_auth_headers():
    nonce = secrets.token_hex(16)
    hmac_val = hmac.new(
        bytes.fromhex(SESSION_KEY), 
        nonce.encode(), 
        hashlib.sha256
    ).hexdigest()
    return {
        "Entity-ID": ENTITY_ID,
        "Nonce": nonce,
        "HMAC": hmac_val
    }

def validate_request(headers):
    entity_id = headers.get("Entity-ID")
    nonce = headers.get("Nonce")
    received_hmac = headers.get("HMAC")
    
    if not all([entity_id, nonce, received_hmac]):
        return False
    
    response = requests.post(
        f"{TRA_URL}/authenticate",
        json={"entity_id": entity_id, "nonce": nonce, "hmac": received_hmac}
    )
    return response.status_code == 200

class CNNClassifier(BaseEstimator, ClassifierMixin):
    def __init__(self, input_shape):
        self.input_shape = input_shape
        self.model = self.buildmdl()

    def buildmdl(self):
        model = Sequential()
        model.add(Input(shape=(self.input_shape, 1)))  
        model.add(Conv1D(64, 2, activation='relu'))
        model.add(Flatten())  
        model.add(Dense(800, activation='relu'))  
        model.add(Dropout(0.5))
        model.add(Dense(1, activation='sigmoid'))
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model

    def fit(self, X, y):
        X = X.reshape(X.shape[0], self.input_shape, 1)
        self.model.fit(X, y, epochs=1, batch_size=32, verbose=1)
        return self

    def predict(self, X):
        X = X.reshape(X.shape[0], self.input_shape, 1)
        return (self.model.predict(X) > 0.5).astype("int32").flatten()

    def predict_proba(self, X):
        X = X.reshape(X.shape[0], self.input_shape, 1)
        proba = self.model.predict(X)
        return np.hstack((1 - proba, proba))  

class LocalPredictor:
    def __init__(self):
        self.selectdfeats = [
            "protocol_type", "service", "flag", "land", "duration", "src_bytes", "dst_bytes", 
            "wrong_fragment", "urgent", "hot", "srv_count", "serror_rate", "srv_serror_rate", 
            "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
            "dst_host_count", "dst_host_srv_count", 
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
            "dst_host_same_src_port_rate", "dst_host_serror_rate", 
            "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        ]                    
        self.standscalr = StandardScaler()
        self.onehotenc = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        self.data = pd.read_csv("KDD.csv")
        self.tempbuffr = pd.DataFrame(columns=self.data.columns)
        self.trainall()
    
    def prepdata(self, data, trainng=False):
        catfeats = ["protocol_type", "service", "flag", "land"]
        data[catfeats] = data[catfeats].fillna('NA').astype(str)
        numfeats = self.selectdfeats[4:]
        data[numfeats] = data[numfeats].fillna(0)
        data = data[self.selectdfeats]

        if trainng:
            encat = self.onehotenc.fit_transform(data[catfeats])
        else:
            encat = self.onehotenc.transform(data[catfeats])

        if trainng:
            scalenum = self.standscalr.fit_transform(data[numfeats])
        else:
            scalenum = self.standscalr.transform(data[numfeats])
        
        return np.hstack((encat, scalenum))
    
    def trainall(self):
        if not self.tempbuffr.empty:
            data_combined = pd.concat([self.data, self.tempbuffr], ignore_index=True)
        else:
            data_combined = self.data

        X = data_combined[self.selectdfeats]
        y = data_combined["classnum"]

        Xtrain, Xtest, ytrain, ytest = train_test_split(X, y, test_size=0.3, random_state=42)
        Xtrainpre = self.prepdata(Xtrain, trainng=True)
        Xtestpre = self.prepdata(Xtest, trainng=False)

        num_features = Xtrainpre.shape[1]  

        self.base_models = [
            ('svm', SVC(probability=True)),
            ('knn', KNeighborsClassifier()),
            ('dt', DecisionTreeClassifier()),
            ('cnn', CNNClassifier(input_shape=num_features))
        ]

        for name, model in self.base_models:
            if name == "cnn":
                Xtrain_cnn = Xtrainpre.reshape(Xtrainpre.shape[0], num_features, 1)
                model.fit(Xtrain_cnn, ytrain)
            else:
                model.fit(Xtrainpre, ytrain)

        self.ensem = VotingClassifier(
            estimators=self.base_models,
            voting='soft' 
        )
        self.ensem.fit(Xtrainpre, ytrain)

        self.update_weights_based_on_accuracy(Xtestpre, ytest)

        ypred = self.ensem.predict(Xtestpre)
        acc = accuracy_score(ytest, ypred)
        print(f"Ensemble Classifier Acc: {acc:.4f}")

    def predict_batch(self, packets):
        packet_df = pd.DataFrame(packets)
        Xpreprocessed = self.prepdata(packet_df, trainng=False)
        num_features = Xpreprocessed.shape[1]  
        X_cnn = Xpreprocessed.reshape(Xpreprocessed.shape[0], num_features, 1)

        cnn_predictions = (self.base_models["cnn"].predict(X_cnn) > 0.5).astype("int32").flatten()
        ensemble_predictions = self.ensem.predict(Xpreprocessed)

        final_predictions = ["anomaly" if ens == "anomaly" or cnn == 1 else "normal" 
                             for ens, cnn in zip(ensemble_predictions, cnn_predictions)]

        self.tempbuffr = pd.concat([self.tempbuffr, packet_df[np.array(final_predictions) == "anomaly"]], ignore_index=True)
        return final_predictions
    
    def update_weights_based_on_accuracy(self, Xtest, ytest):

        accuracies = []
        
        for name, model in self.ensem.estimators:
            if name == "cnn":
                Xtest_cnn = Xtest.reshape(Xtest.shape[0], Xtest.shape[1], 1)
                ypred = (model.predict(Xtest_cnn) > 0.5).astype("int32").flatten()
            else:
                ypred = model.predict(Xtest)
            
            acc = accuracy_score(ytest, ypred)
            accuracies.append(acc)
            print(f"{name} Accuracy: {acc:.4f}")
        
        total_accuracy = sum(accuracies)
        normalized_weights = [acc / total_accuracy for acc in accuracies]
        
        self.ensem.weights = normalized_weights
        
        print("Normalized Weights:")
        for (name, model), weight in zip(self.ensem.estimators, self.ensem.weights):
            print(f"{name}: {weight:.4f}")
    
    def get_weights(self):
        return self.ensem.weights
    
    def set_weights(self, weights):
        if len(weights) == len(self.ensem.estimators):
            self.ensem.weights = weights
            print("Weights updated successfully.")
        else:
            print("Error: Invalid number of weights provided.")

local_predictor = LocalPredictor()

@app.route('/get_weights', methods=['GET'])
def get_weights():
    if not validate_request(request.headers):
        return jsonify({"error": "Authentication failed"}), 401
    
    weights = local_predictor.get_weights()
    return jsonify({"weights": weights})

@app.route('/update_weights', methods=['POST'])
def update_weights():
    if not validate_request(request.headers):
        return jsonify({"error": "Authentication failed"}), 401
    
    weights = request.json.get("weights")
    if not weights:
        return jsonify({"error": "No weights provided"}), 400
    
    local_predictor.set_weights(weights)
    return jsonify({"message": "Weights updated successfully"})

featureslist = []
batch_data = []  
sessions = defaultdict(list)

protocol_map = {6: "tcp", 17: "udp", 1: "icmp"}  
service_mapping = {
    80: "http", 21: "ftp", 23: "telnet", 25: "smtp", 443: "https", 22: "ssh", 
    53: "dns", 110: "pop3", 995: "pop3s", 143: "imap", 993: "imaps", 161: "snmp",
    3306: "mysql", 5432: "postgresql", 8080: "http_alt"
}

def extractfeatures(packet):
    if IP in packet and TCP in packet:
        sessionkey = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
        sessions[sessionkey].append(packet)

def computesessionfeatures(sessionpackt):
    features = {}

    features["protocol_type"] = protocol_map.get(sessionpackt[0][IP].proto, "other")
    features["service"] = str(sessionpackt[0][TCP].dport)
    features["service"] = pd.Series([features["service"]]).map(service_mapping).fillna("other").iloc[0]
    features["flag"] = str(sessionpackt[0][TCP].flags)

    features["duration"] = sessionpackt[-1].time - sessionpackt[0].time
    features["land"] = int(sessionpackt[0][IP].src == sessionpackt[0][IP].dst and sessionpackt[0][TCP].sport == sessionpackt[0][TCP].dport)

    srcbytes = sum(len(p) for p in sessionpackt if p[IP].src == sessionpackt[0][IP].src)
    dstbytes = sum(len(p) for p in sessionpackt if p[IP].dst == sessionpackt[0][IP].dst)
    wrong_fragment = sum(1 for p in sessionpackt if p.haslayer(IP) and p[IP].flags == 1)
    urgent = any(p.haslayer(TCP) and getattr(p[TCP], 'urg', 0) for p in sessionpackt)

    serror_count = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x04)
    rerror_count = sum(1 for p in sessionpackt if p.haslayer(TCP) and p[TCP].flags & 0x01)
    
    hot = len(set(p[IP].src for p in sessionpackt))
    srv_count = len(sessionpackt)

    diffsrvcount = set(p[IP].dst for p in sessionpackt)

    features["src_bytes"] = srcbytes
    features["dst_bytes"] = dstbytes
    features["wrong_fragment"] = wrong_fragment
    features["urgent"] = int(urgent)
    features["hot"] = hot
    features["srv_count"] = srv_count
    features["serror_rate"] = serror_count / srv_count if srv_count > 0 else 0
    features["srv_serror_rate"] = features["serror_rate"]
    features["rerror_rate"] = rerror_count / srv_count if srv_count > 0 else 0
    features["srv_rerror_rate"] = features["rerror_rate"]
    features["same_srv_rate"] = len(set(p[TCP].dport for p in sessionpackt)) / srv_count if srv_count > 0 else 0
    features["diff_srv_rate"] = len(diffsrvcount) / srv_count if srv_count > 0 else 0
    features["srv_diff_host_rate"] = len(set(p[IP].src for p in sessionpackt)) / srv_count if srv_count > 0 else 0

    features["dst_host_count"] = len(diffsrvcount)
    features["dst_host_srv_count"] = len(set((p[IP].dst, p[TCP].dport) for p in sessionpackt))

    dst_host_same_srv_rate = sum(1 for p in sessionpackt if p[TCP].dport == sessionpackt[0][TCP].dport) / srv_count if srv_count > 0 else 0
    dst_host_diff_srv_rate = len(set(p[TCP].dport for p in sessionpackt)) / srv_count if srv_count > 0 else 0
    dst_host_same_src_port_rate = sum(1 for p in sessionpackt if p[TCP].sport == sessionpackt[0][TCP].sport) / srv_count if srv_count > 0 else 0

    dst_host_serror_rate = serror_count / srv_count if srv_count > 0 else 0
    dst_host_srv_serror_rate = dst_host_serror_rate
    dst_host_rerror_rate = rerror_count / srv_count if srv_count > 0 else 0
    dst_host_srv_rerror_rate = dst_host_rerror_rate

    features["dst_host_same_srv_rate"] = dst_host_same_srv_rate
    features["dst_host_diff_srv_rate"] = dst_host_diff_srv_rate
    features["dst_host_same_src_port_rate"] = dst_host_same_src_port_rate
    

    features["dst_host_srv_diff_host_rate"] = len(set(p[IP].src for p in sessionpackt)) / srv_count if srv_count > 0 else 0

    features["dst_host_serror_rate"] = dst_host_serror_rate
    features["dst_host_srv_serror_rate"] = dst_host_srv_serror_rate
    features["dst_host_rerror_rate"] = dst_host_rerror_rate
    features["dst_host_srv_rerror_rate"] = dst_host_srv_rerror_rate
    return features

def packetcallback(packet):
    extractfeatures(packet)
    if len(sessions) > 0:
        for sessionkey in list(sessions.keys()):
            sessionpackt = sessions[sessionkey]
            if len(sessionpackt) > 1: 
                features = computesessionfeatures(sessionpackt)
                dataset_columns = [
                   "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
                    "wrong_fragment", "urgent", "hot", "srv_count", "serror_rate", "srv_serror_rate",
                    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
                    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
                    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
                ]
                ordered_features = {col: features.get(col, 0) for col in dataset_columns}
                featureslist.append(ordered_features)
                batch_data.append(features)
                if len(batch_data) >= 10:
                    process_batch()

def process_batch():
    global batch_data
    try:
        batch_df = pd.DataFrame(batch_data)
        
        required_columns = local_predictor.selectdfeats
        for col in required_columns:
            if col not in batch_df.columns:
                batch_df[col] = 0
        
        predictions = local_predictor.predict_batch(batch_df)
        print("Batch processed. Predictions:", predictions)

        if all(pred == "anomaly" for pred in predictions):  
            requests.post("http://localhost:5550/error")

        batch_data = []  
    except Exception as e:
        print(f"Error processing batch: {e}")

def fetch_weights_from_cloud():

    try:
        headers = generate_auth_headers()
        response = requests.get(
            f"{CLOUD_SERVER_URL}/get_weights",
            headers=headers
        )
        if response.status_code == 200:
            weights = response.json().get("weights")
            return weights
        else:
            print(f"Failed to fetch weights: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching weights from cloud: {e}")
        return None

def send_weights_to_cloud(weights):
    try:
        headers = generate_auth_headers()
        response = requests.post(
            f"{CLOUD_SERVER_URL}/update_weights",
            json={"weights": weights},
            headers=headers
        )
        if response.status_code == 200:
            print("Weights sent to cloud server successfully.")
            return True
        else:
            print(f"Failed to send weights: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error sending weights to cloud: {e}")
        return False

def periodtrain():
    while True:
        time.sleep(3600)  
        local_weights = local_predictor.get_weights()
        if not local_weights:
            print("No local weights available.")
            continue
        if not send_weights_to_cloud(local_weights):
            print("Failed to send weights to the cloud server.")
            continue
        updated_weights = fetch_weights_from_cloud()
        if not updated_weights:
            print("Failed to fetch updated weights from the cloud server.")
            continue

        local_predictor.set_weights(updated_weights)
        print("Local model weights updated successfully.")

threading.Thread(target=periodtrain, daemon=True).start()

def start_flask_server():
    app.run(host='0.0.0.0', port=5000)

register_with_tra()
threading.Thread(target=start_flask_server, daemon=True).start()

print("Starting packet capture...")
sniff(prn=packetcallback ,store=0, filter="tcp")
print("📁 Saving Captured Packet Features...")
pd.DataFrame(featureslist).to_csv('packet_features.csv', index=False)
print("✅ Packet Features Saved to packet_features.csv")