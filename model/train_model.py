import sys
import os
from pathlib import Path

# This tells Python: "The root of the project is one folder up from here"
# So it can correctly find 'model.features'
sys.path.append(str(Path(__file__).resolve().parent.parent))

import re
import numpy as np
import joblib
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.svm import LinearSVC  
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, classification_report
from sklearn.naive_bayes import MultinomialNB
from model.features import TextStatsExtractor

def clean_df(input_df, keep_duplicates=False):
    cleaned = input_df.dropna(subset=['body', 'label'])
    cleaned = cleaned[cleaned['body'].str.strip().str.len() > 10]
    cleaned['body'] = cleaned['body'].str[:10000] 
    cleaned['body'] = cleaned['body'].str.replace(r'\(truncated \d+ characters\)', '', regex=True)
    cleaned['body'] = cleaned['body'].str.replace(r'\.{3}', '', regex=True)
    if not keep_duplicates:
        cleaned = cleaned.drop_duplicates(subset=['body'])
    return cleaned



if __name__ == "__main__":

    df = pd.read_csv(r"model\Phishing_Email.csv")  
    df2 = pd.read_csv(r"model\combined_dataset.csv")  
    df3 = pd.read_csv(r"model\CEAS_08.csv")  

    df['label'] = df['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})
    df.rename(columns={'Email Text': 'body'}, inplace=True)
    df2.rename(columns={'text_combined': 'body'}, inplace=True) 
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


    pipe_lr_word = Pipeline([
        ('tfidf_word', TfidfVectorizer(analyzer='word', ngram_range=(1, 2), max_features=3000)),
        ('lr', LogisticRegression(class_weight='balanced', solver='liblinear'))
    ])


    pipe_svm_char = Pipeline([
        ('tfidf_char', TfidfVectorizer(analyzer='char', ngram_range=(3, 4), max_features=3000)),
        ('svm', LinearSVC(class_weight='balanced', random_state=42))
    ])

    pipe_nb_counts = Pipeline([
        ('count_vec', CountVectorizer(max_features=3000)),
        ('nb', MultinomialNB())
    ])


    pipe_rf_stats = Pipeline([
        ('stats', TextStatsExtractor()),
        ('rf', RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42))
    ])

    model = StackingClassifier(
        estimators=[
            ('word_view', pipe_lr_word),
            ('char_view', pipe_svm_char),
            ('count_view', pipe_nb_counts),
            ('stats_view', pipe_rf_stats)
        ],
        final_estimator=LogisticRegression(class_weight='balanced'),
        cv=3,
        n_jobs=1
    )

    print("Training Stacking Classifier with Heterogeneous Features...")
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


    joblib.dump(model, r"model\\phishing_model_full.pkl")
    print("\nModel (trained on dt + dt2 + dt3) saved as phishing_model_full.pkl")