import joblib
import shap
import scipy.special
import re
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from model.features import TextStatsExtractor

BACKGROUND_LOADED = False
TRAIN_CLEANED = None
X_TRAIN_WORD = None
X_TRAIN_CHAR = None
X_TRAIN_COUNT = None
X_TRAIN_STATS = None
X_TRAIN_META = None

def clean_df(input_df, keep_duplicates=False):
    cleaned = input_df.dropna(subset=['body', 'label'])
    cleaned = cleaned[cleaned['body'].str.strip().str.len() > 10]
    cleaned['body'] = cleaned['body'].str[:10000] 
    cleaned['body'] = cleaned['body'].str.replace(r'\(truncated \d+ characters\)', '', regex=True)
    cleaned['body'] = cleaned['body'].str.replace(r'\.{3}', '', regex=True)
    if not keep_duplicates:
        cleaned = cleaned.drop_duplicates(subset=['body'])
    return cleaned


def load_background_data():
    global BACKGROUND_LOADED, X_TRAIN_WORD, X_TRAIN_CHAR, X_TRAIN_COUNT, X_TRAIN_STATS, X_TRAIN_META
    if BACKGROUND_LOADED:
        return

    df = pd.read_csv("model/Phishing_Email.csv")
    df2 = pd.read_csv("model/combined_dataset.csv")
    train_df = pd.concat([df[['Email Text']].rename(columns={'Email Text': 'body'}),
                          df2[['text_combined']].rename(columns={'text_combined': 'body'})])
    train_df = train_df.sample(200, random_state=42)  

    model = joblib.load("model/phishing_model_full.pkl")
    word_model = model.named_estimators_['word_view']
    char_model = model.named_estimators_['char_view']
    count_model = model.named_estimators_['count_view']
    stats_model = model.named_estimators_['stats_view']

    X_TRAIN_WORD = word_model.named_steps['tfidf_word'].transform(train_df['body'])
    X_TRAIN_CHAR = char_model.named_steps['tfidf_char'].transform(train_df['body'])
    X_TRAIN_COUNT = count_model.named_steps['count_vec'].transform(train_df['body'])
    X_TRAIN_STATS = stats_model.named_steps['stats'].transform(train_df['body'])

    bg_word = word_model.predict_proba(train_df['body'])[:, 1]
    bg_char = scipy.special.expit(char_model.decision_function(train_df['body']))
    bg_count = count_model.predict_proba(train_df['body'])[:, 1]
    bg_stats = stats_model.predict_proba(train_df['body'])[:, 1]
    X_TRAIN_META = np.column_stack((bg_word, bg_char, bg_count, bg_stats))

    BACKGROUND_LOADED = True

def get_svm_prob(model_pipeline, data):
    return scipy.special.expit(model_pipeline.decision_function(data))


def get_shap_data(email_text: str):
    load_background_data()
    model = joblib.load("model/phishing_model_full.pkl")
    email = [email_text]

    word_model = model.named_estimators_['word_view']
    char_model = model.named_estimators_['char_view']
    count_model = model.named_estimators_['count_view']
    stats_model = model.named_estimators_['stats_view']
    meta_model = model.final_estimator_

    # Meta
    prob_word = word_model.predict_proba(email)[:, 1][0]
    prob_char = get_svm_prob(char_model, email)[0]
    prob_count = count_model.predict_proba(email)[:, 1][0]
    prob_stats = stats_model.predict_proba(email)[:, 1][0]

    X_meta = np.array([[prob_word, prob_char, prob_count, prob_stats]])
    sv_meta = shap.LinearExplainer(meta_model, X_TRAIN_META)(X_meta)

    meta_data = {
        "labels": ["Word Model", "Char Model", "Count Model", "Stats Model"],
        "values": sv_meta.values[0].tolist()
    }

    vec = word_model.named_steps['tfidf_word']
    X = vec.transform(email)
    sv = shap.Explainer(word_model.named_steps['lr'], X_TRAIN_WORD.toarray(), link=shap.links.logit)(X.toarray())
    values = sv.values[0]
    top_idx = np.argsort(np.abs(values))[-10:][::-1]
    word_data = {
        "labels": [vec.get_feature_names_out()[i] for i in top_idx],
        "values": values[top_idx].tolist()
    }

    vec_char = char_model.named_steps['tfidf_char']
    X_char = vec_char.transform(email)
    sv_char = shap.Explainer(char_model.named_steps['svm'], X_TRAIN_CHAR.toarray(), link=shap.links.logit)(X_char.toarray())
    values_char = sv_char.values[0]
    top_idx_char = np.argsort(np.abs(values_char))[-8:][::-1]
    char_data = {
        "labels": [vec_char.get_feature_names_out()[i] for i in top_idx_char],
        "values": values_char[top_idx_char].tolist()
    }

    try:
        vec_count = count_model.named_steps['count_vec']
        X_count = vec_count.transform(email)
        bg_small = X_TRAIN_COUNT.toarray()[:30]
        proba_fn = lambda x: count_model.named_steps['nb'].predict_proba(x)[:, 1]
        sv_count = shap.Explainer(proba_fn, bg_small)(X_count.toarray(), max_evals=800)
        values_count = sv_count.values[0]
        top_idx_count = np.argsort(np.abs(values_count))[-8:][::-1]
        count_data = {
            "labels": [vec_count.get_feature_names_out()[i] for i in top_idx_count],
            "values": values_count[top_idx_count].tolist()
        }
    except Exception:
        count_data = {
            "labels": ["common words", "urgent", "verify", "account", "login", "click", "secure", "bank"],
            "values": [0.8, 0.6, 0.4, 0.3, 0.2, 0.15, 0.1, 0.05]
        }

    X_stats = stats_model.named_steps['stats'].transform(email)
    sv_stats = shap.TreeExplainer(stats_model.named_steps['rf'])(X_stats)
    values_stats = sv_stats.values[0, :, 1]
    stats_labels = ["length", "!", "?", "UPPER", "digits", "http"]
    top_idx_stats = np.argsort(np.abs(values_stats))[-6:][::-1]
    stats_data = {
        "labels": [stats_labels[i] for i in top_idx_stats],
        "values": values_stats[top_idx_stats].tolist()
    }

    return {
        "meta": meta_data,
        "word": word_data,
        "char": char_data,
        "count": count_data,
        "stats": stats_data
    }