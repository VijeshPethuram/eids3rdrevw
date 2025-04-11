import threading
from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import requests
from sklearn.ensemble import VotingClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import time
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, Flatten, Dropout, Input
from sklearn.base import BaseEstimator, ClassifierMixin

app = Flask(__name__)

class CNNClassifier(BaseEstimator, ClassifierMixin):
    def __init__(self, input_shape):
        self.input_shape = input_shape
        self.model = self.buildmodl()

    def buildmodl(self):
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

class CloudSrvr:
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
        self.data = pd.read_csv("KDD.csv").iloc[:5000]
        self.tempbuffr = pd.DataFrame(columns=self.data.columns)
        self.trainall()
        self.client_weights = [] 
    
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

        base_models = [
            ('svm', SVC(probability=True)),
            ('knn', KNeighborsClassifier()),
            ('dt', DecisionTreeClassifier()),
            ('cnn', CNNClassifier(input_shape=num_features))
        ]

        for name, model in base_models:
            if name == "cnn":
                Xtrain_cnn = Xtrainpre.reshape(Xtrainpre.shape[0], num_features, 1)
                model.fit(Xtrain_cnn, ytrain)
            else:
                model.fit(Xtrainpre, ytrain)

        self.ensem = VotingClassifier(
            estimators=base_models,
            voting='soft' 
        )

        self.ensem.fit(Xtrainpre, ytrain)

        self.updateweightsbyaccuracy(Xtestpre, ytest)

        ypred = self.ensem.predict(Xtestpre)
        acc = accuracy_score(ytest, ypred)
        print(f"Voting Classifier Acc: {acc:.4f}")
    
    def predict_batch(self, packets):
        packet_df = pd.DataFrame(packets)
        Xpreprocessed = self.prepdata(packet_df, trainng=False)
        num_features = Xpreprocessed.shape[1]  
        X_cnn = Xpreprocessed.reshape(Xpreprocessed.shape[0], num_features, 1)

        cnn_predictions = (self.machinemodels["cnn"].predict(X_cnn) > 0.5).astype("int32").flatten()
        ensemble_predictions = self.ensem.predict(Xpreprocessed)

        final_predictions = ["anomaly" if ens == "anomaly" or cnn == 1 else "normal" 
                             for ens, cnn in zip(ensemble_predictions, cnn_predictions)]

        self.tempbuffr = pd.concat([self.tempbuffr, packet_df[np.array(final_predictions) == "anomaly"]], ignore_index=True)
        return final_predictions
    
    def updateweightsbyaccuracy(self, Xtest, ytest):

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
    
    def update_weights_from_clients(self, client_weights):
        if not client_weights:
            return
        
        mean_weights = np.mean(client_weights, axis=0)
        self.ensem.weights = mean_weights.tolist()
        print("Updated model weights based on client contributions.")

cloudsrv = CloudSrvr()

def periodtrain():
    while True:
        time.sleep(3600)
        cloudsrv.trainall()

threading.Thread(target=periodtrain, daemon=True).start()

ENTITY_ID = "cloud_server_1"
SESSION_KEY = None

def register_with_tra():
    global SESSION_KEY
    response = requests.post(
        "http://localhost:6000/register",
        json={"entity_id": ENTITY_ID, "entity_type": "cloud_server"}
    )
    if response.status_code == 201:
        SESSION_KEY = response.json()["session_key"]
        print("Cloud server registered with TRA. SKEY: ", SESSION_KEY)

def validate_request(headers):
    entity_id = headers.get("Entity-ID")
    nonce = headers.get("Nonce")
    received_hmac = headers.get("HMAC")
    
    if not all([entity_id, nonce, received_hmac]):
        return False
    
    response = requests.post(
        "http://localhost:6000/authenticate",
        json={"entity_id": entity_id, "nonce": nonce, "hmac": received_hmac}
    )
    return response.status_code == 200

@app.route('/predict', methods=['POST'])
def predict_packet():
    if not validate_request(request.headers):
        return jsonify({"error": "Authentication failed"}), 401
    
    packets = request.json  
    predictions = cloudsrv.predict_batch(packets)
    predictions_list = predictions.tolist()
    
    return jsonify({"predictions": predictions_list})

@app.route('/get_weights', methods=['GET'])
def get_weights():
    if not validate_request(request.headers):
        return jsonify({"error": "Authentication failed"}), 401
    
    weights = cloudsrv.get_weights()
    return jsonify({"weights": weights})

@app.route('/update_weights', methods=['POST'])
def update_weights():
    if not validate_request(request.headers):
        return jsonify({"error": "Authentication failed"}), 401
    
    client_weights = request.json.get("weights")
    if not client_weights:
        return jsonify({"error": "No weights provided"}), 400
    
    cloudsrv.client_weights.append(client_weights)
    cloudsrv.update_weights_from_clients(cloudsrv.client_weights)
    
    return jsonify({"message": "Weights updated successfully"})

register_with_tra()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)