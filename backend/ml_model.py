import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import os
import json
from datetime import datetime

class FraudMLModel:
    def __init__(self, model_path='model.pkl', scaler_path='scaler.pkl'):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = StandardScaler()
        self.le_upi = LabelEncoder()
        self.le_bank = LabelEncoder()
        self.is_trained = False
        self.load_model()
    
    def load_model(self):
        """Load pre-trained model and scaler"""
        # Load model
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            self.is_trained = True
        else:
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
        
        # Load scaler
        if os.path.exists(self.scaler_path):
            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
    
    def _create_default_model(self):
        """Create a default ML model"""
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
    
    def extract_features(self, upi_id, bank_handle, risk_score, historical_data=None):
        """Extract features for prediction with more sophisticated engineering"""
        features = []
        
        # Basic features
        features.append(len(upi_id))  # UPI ID length
        features.append(sum(c.isdigit() for c in upi_id))  # Digit count
        features.append(sum(c.isalpha() for c in upi_id))  # Letter count
        features.append(upi_id.count('@'))  # @ symbol count
        
        # Risk-based features
        features.append(risk_score)
        features.append(1 if bank_handle else 0)
        
        # Pattern features
        features.append(1 if any(c.isdigit() for c in upi_id.split('@')[0]) else 0)  # Has numbers in handle
        features.append(len(upi_id.split('@')[0]) if '@' in upi_id else 0)  # Handle length
        
        # Bank handle features
        if bank_handle:
            bank_name_lower = bank_handle.lower()
            features.append(1 if bank_name_lower in ['sbi', 'hdfc', 'icici', 'axis', 'kotak'] else 0)  # Top bank
            features.append(len(bank_handle))  # Bank handle length
        else:
            features.append(0)
            features.append(0)
        
        # Historical features (if available)
        if historical_data:
            features.append(historical_data.get('transaction_count', 0))
            features.append(historical_data.get('avg_amount', 0))
            features.append(historical_data.get('last_activity_days', 0))
        else:
            features.append(0)
            features.append(0)
            features.append(0)
        
        return features
    
    def predict(self, features):
        """Predict fraud probability with scaling"""
        if self.model is None:
            return 0.5
        
        # Scale features
        try:
            scaled_features = self.scaler.transform([features])
            return self.model.predict_proba(scaled_features)[0][1]
        except:
            return self.model.predict_proba([features])[0][1]
    
    def predict_fraud(self, upi_id, bank_handle, risk_score, historical_data=None):
        """Main prediction method with enhanced output"""
        features = self.extract_features(upi_id, bank_handle, risk_score, historical_data)
        fraud_probability = self.predict(features)
        
        # Determine risk category with more granular levels
        if fraud_probability > 0.8:
            risk_category = 'Critical'
        elif fraud_probability > 0.6:
            risk_category = 'High'
        elif fraud_probability > 0.4:
            risk_category = 'Medium'
        elif fraud_probability > 0.2:
            risk_category = 'Low'
        else:
            risk_category = 'Minimal'
        
        # Generate recommendations
        recommendations = self._generate_recommendations(fraud_probability, risk_score)
        
        return {
            'upi_id': upi_id,
            'fraud_probability': round(fraud_probability * 100, 2),
            'risk_category': risk_category,
            'ml_risk_score': round(fraud_probability * 100),
            'rule_based_score': risk_score,
            'combined_score': round((fraud_probability * 100 + risk_score) / 2),
            'recommendations': recommendations,
            'model_confidence': round(max(fraud_probability, 1 - fraud_probability) * 100, 2),
            'analyzed_at': datetime.now().isoformat()
        }
    
    def _generate_recommendations(self, fraud_prob, risk_score):
        """Generate safety recommendations based on analysis"""
        recommendations = []
        
        if fraud_prob > 0.7:
            recommendations.append("⚠️ Do NOT send money to this UPI ID")
            recommendations.append("⚠️ This UPI ID has been flagged as high risk")
        elif fraud_prob > 0.4:
            recommendations.append("⚡ Exercise caution when transacting")
            recommendations.append("⚡ Verify recipient through alternate channel")
        else:
            recommendations.append("✅ Standard verification passed")
        
        if risk_score > 70:
            recommendations.append("🔴 High risk score from rule-based analysis")
        
        return recommendations
    
    def train(self, X_train, y_train):
        """Train the model with more robust approach"""
        # Scale features first
        X_scaled = self.scaler.fit_transform(X_train)
        
        # Train model
        self.model.fit(X_scaled, y_train)
        self.save_model()
        self.is_trained = True
    
    def train_with_validation(self, X, y, test_size=0.2):
        """Train with validation split and return metrics"""
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Save
        self.save_model()
        self.is_trained = True
        
        return {
            'accuracy': round(accuracy * 100, 2),
            'report': classification_report(y_test, y_pred)
        }
    
    def save_model(self):
        """Save model and scaler to files"""
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
    
    def get_feature_importance(self):
        """Get feature importance from the model"""
        if hasattr(self.model, 'feature_importances_'):
            feature_names = [
                'upi_length', 'digit_count', 'letter_count', 'at_symbols',
                'risk_score', 'has_bank_handle', 'handle_has_numbers',
                'handle_length', 'top_bank', 'bank_handle_length',
                'transaction_count', 'avg_amount', 'days_since_activity'
            ]
            importance = self.model.feature_importances_
            return dict(zip(feature_names, importance.tolist()))
        return {}
    
    def retrain_with_feedback(self, upi_id, actual_fraud, bank_handle, risk_score):
        """Retrain model with user feedback for continuous learning"""
        if not hasattr(self, '_feedback_data'):
            self._feedback_data = []
        
        features = self.extract_features(upi_id, bank_handle, risk_score)
        self._feedback_data.append((features, actual_fraud))
        
        # Retrain after every 10 feedback entries
        if len(self._feedback_data) >= 10:
            X = [f[0] for f in self._feedback_data]
            y = [f[1] for f in self._feedback_data]
            self.train(X, y)
            self._feedback_data = []  # Reset after training