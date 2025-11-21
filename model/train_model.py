import re
import numpy as np
import joblib
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.svm import LinearSVC 
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, f1_score, classification_report
import pandas as pd
from sklearn.naive_bayes import MultinomialNB


df = pd.read_csv("Phishing_Email.csv") 
df2 = pd.read_csv("Phishing_validation_emails.csv")  
df3 = pd.read_csv("CEAS_08.csv", encoding="latin1")  


df['label'] = df['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})
df.rename(columns={'Email Text': 'body'}, inplace=True)
df2['label'] = df2['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})
df2.rename(columns={'Email Text': 'body'}, inplace=True)
df3['body'] = df3['body'].astype(str)


train_df = pd.concat([
    df[['body', 'label']],
    df2[['body', 'label']]
], ignore_index=True)


test_df = df3[['body', 'label']]

print("Train data shape (dt + dt2):", train_df.shape)
print(train_df['label'].value_counts())
print("Test data shape (dt3):", test_df.shape)
print(test_df['label'].value_counts())

print("----------------------------------------------------")


def clean_df(input_df, keep_duplicates=False):
    cleaned = input_df.dropna(subset=['body', 'label'])
    cleaned = cleaned[cleaned['body'].str.strip().str.len() > 10]
    cleaned['body'] = cleaned['body'].str[:10000]  
    cleaned['body'] = cleaned['body'].str.replace(r'\(truncated \d+ characters\)', '', regex=True)
    cleaned['body'] = cleaned['body'].str.replace(r'\.{3}', '', regex=True)
    if not keep_duplicates:
        cleaned = cleaned.drop_duplicates(subset=['body'])
    return cleaned

train_df = clean_df(train_df, keep_duplicates=False)
test_df = clean_df(test_df, keep_duplicates=True)

print("Cleaned train shape (dt + dt2):", train_df.shape)
print(train_df['label'].value_counts())
print("Cleaned test shape (dt3):", test_df.shape)
print(test_df['label'].value_counts())

print("----------------------------------------------------")


X_train = train_df["body"].fillna("unknown").astype(str)
y_train = train_df["label"].astype(int)
X_test = test_df["body"].fillna("unknown").astype(str)
y_test = test_df["label"].astype(int)



tfidf = TfidfVectorizer(
    ngram_range=(1, 1),
    lowercase=True,
    sublinear_tf=True,
    stop_words="english",
    max_df=0.75,
    min_df=10,
    max_features=3000
)


model = Pipeline([
    ("tfidf", tfidf),
    ("clf", LogisticRegression(
        C=10,
        class_weight="balanced",
        solver="liblinear", 
        max_iter=100,
    ))
])


print("Running 5-fold cross-validation on train set (dt + dt2)...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_acc = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy")
cv_f1 = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1")

print("\n===== Cross-Validation Results (Train set: dt + dt2) =====")
print("CV Accuracy: %.4f (+/- %.4f)" % (cv_acc.mean(), cv_acc.std()))
print("CV F1 Score: %.4f (+/- %.4f)" % (cv_f1.mean(), cv_f1.std()))

print("\nTraining final model on train set (dt + dt2)...")
model.fit(X_train, y_train)
print("Training done!")

y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n===== Test Set Results (on unseen dt3) =====")
print("Accuracy:", acc)
print("F1 Score:", f1)
print("\nClassification Report:\n", classification_report(y_test, y_pred))



print("\nCombining all datasets (dt + dt2 + dt3) for final training...")
full_df = pd.concat([train_df, test_df], ignore_index=True)
X_full = full_df["body"].fillna("unknown").astype(str)
y_full = full_df["label"].astype(int)

print("Full dataset shape:", full_df.shape)
print(full_df['label'].value_counts())


print("\nTraining model on full dataset (dt + dt2 + dt3)...")
model.fit(X_full, y_full)
print("Training done!")


joblib.dump(model, "phishing_model_full.pkl")
print("\nModel (trained on dt + dt2 + dt3) saved as phishing_model_full.pkl")