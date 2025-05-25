from sklearn.ensemble import RandomForestClassifier
import numpy as np

def train_federated_model():
    honeypot1 = np.array([[0.8, 1, 1], [0.9, 1, 0]])
    honeypot2 = np.array([[0.4, 0, 1], [0.3, 0, 0]])
    honeypot3 = np.array([[0.7, 1, 1], [0.6, 1, 1]])

    X = np.vstack([honeypot1, honeypot2, honeypot3])
    y = np.array([1, 1, 0, 0, 1, 1])

    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)
    return model


federated_model = train_federated_model()

def validate_threat(trust_score, honeypot_match, osint_match):
    feature_vector = np.array([[trust_score, honeypot_match, osint_match]])
    prediction = federated_model.predict(feature_vector)[0]
    probability = federated_model.predict_proba(feature_vector)[0][1]
    return prediction, round(probability * 100, 2)
