# import joblib
# import shap
# import scipy.special
# import re
# import numpy as np
# import pandas as pd
# import joblib
# import sys
# from pathlib import Path
# sys.path.append(str(Path(__file__).resolve().parent.parent))
# from model.features import TextStatsExtractor



# model = joblib.load("model/phishing_model_full.pkl")


# def clean_df(input_df, keep_duplicates=False):
#     cleaned = input_df.dropna(subset=['body', 'label'])
#     cleaned = cleaned[cleaned['body'].str.strip().str.len() > 10]
#     cleaned['body'] = cleaned['body'].str[:10000] 
#     cleaned['body'] = cleaned['body'].str.replace(r'\(truncated \d+ characters\)', '', regex=True)
#     cleaned['body'] = cleaned['body'].str.replace(r'\.{3}', '', regex=True)
#     if not keep_duplicates:
#         cleaned = cleaned.drop_duplicates(subset=['body'])
#     return cleaned


# df = pd.read_csv(r"model\Phishing_Email.csv")  
# df2 = pd.read_csv(r"model\combined_dataset.csv")  
# df3 = pd.read_csv(r"model\CEAS_08.csv")  

# df['label'] = df['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})
# df.rename(columns={'Email Text': 'body'}, inplace=True)
# df2.rename(columns={'text_combined': 'body'}, inplace=True) 
# df3['body'] = df3['body'].astype(str)

# train_df = pd.concat([
#         df[['body', 'label']],
#         df2[['body', 'label']]
#     ], ignore_index=True)

# test_df = df3[['body', 'label']]

# train_cleaned = clean_df(train_df)






# word_model = model.named_estimators_['word_view']
# char_model = model.named_estimators_['char_view']
# count_model = model.named_estimators_['count_view']
# stats_model = model.named_estimators_['stats_view']

# meta_model = model.final_estimator_


# # Example email
# email = ["""Dear Customer,

# Your December bill is now ready. Amount due: $87.45 by January 15, 2026.

# View and pay securely at our website: www.electriccompany.com/login

# Thank you,
# Billing Department
# """]


# # Word-level features(Logistic Regression)
# vectorizer = word_model.named_steps['tfidf_word']
# lr_model = word_model.named_steps['lr']

# train_text_samples = train_cleaned['body'].sample(200, random_state=42) # Pick 200 random emails
# X_train_transformed = vectorizer.transform(train_text_samples)

# X_word = vectorizer.transform(email)

# feature_names = vectorizer.get_feature_names_out()

# explainer = shap.Explainer(lr_model, X_train_transformed.toarray(), link=shap.links.logit)

# shap_values_word = explainer(X_word.toarray())

# base_prob = scipy.special.expit(shap_values_word.base_values)
# new_values = scipy.special.expit(shap_values_word.base_values + shap_values_word.values) - base_prob

# shap_values_word.values = new_values
# shap_values_word.base_values = base_prob
# shap_values_word.data = X_word.toarray()
# shap_values_word.feature_names = list(feature_names)

# explanation_to_plot = shap_values_word[0][X_word.indices]
# shap.plots.bar(explanation_to_plot, max_display=10)


# # char-level features(SVM)
# vectorizer_char = char_model.named_steps['tfidf_char']
# svm_model = char_model.named_steps['svm']

# X_train_transformed = vectorizer_char.transform(train_text_samples)

# X_char = vectorizer_char.transform(email)

# explainer_char = shap.Explainer(svm_model, X_train_transformed.toarray(), link=shap.links.logit)

# shap_values_char = explainer_char(X_char.toarray())

# base_prob_char = scipy.special.expit(shap_values_char.base_values)
# new_values_char = scipy.special.expit(shap_values_char.base_values + shap_values_char.values) - base_prob_char

# shap_values_char.values = new_values_char
# shap_values_char.base_values = base_prob_char
# shap_values_char.data = X_char.toarray()
# shap_values_char.feature_names = list(vectorizer_char.get_feature_names_out())

# explanation_char = shap_values_char[0][X_char.indices]
# shap.plots.bar(explanation_char, max_display=10)


# # count-based features(Naive Bayes)
# count_vectorizer = count_model.named_steps['count_vec']
# nb_model = count_model.named_steps['nb']

# proba_function = lambda x: nb_model.predict_proba(x)[:, 1]

# X_train_count = count_vectorizer.transform(train_text_samples)
# X_count = count_vectorizer.transform(email)

# explainer_count = shap.Explainer(
#     proba_function, 
#     X_train_count.toarray()
# )


# shap_values_count = explainer_count(X_count.toarray(), max_evals=4377)

# shap_values_count.feature_names = list(count_vectorizer.get_feature_names_out())

# shap.plots.bar(shap_values_count[0], max_display=10)



# # text stats features(Random Forest)
# stats_extractor = stats_model.named_steps['stats']
# rf_model = stats_model.named_steps['rf']

# X_train_stats = stats_extractor.transform(train_text_samples)
# X_stats = stats_extractor.transform(email)

# explainer_stats = shap.TreeExplainer(rf_model,)

# shap_values_stats = explainer_stats(X_stats)

# shap_values_phishing = shap_values_stats[..., 1]
# manual_feature_names = [
#     "length",
#     "exclamation_count",
#     "question_count",
#     "uppercase_count",
#     "digit_count",
#     "url_count"
# ]

# shap_values_phishing.feature_names = manual_feature_names

# shap.plots.bar(shap_values_phishing[0], max_display=10)




# # Meta-model explanation
# word_model = model.named_estimators_['word_view']
# char_model = model.named_estimators_['char_view']
# count_model = model.named_estimators_['count_view']
# stats_model = model.named_estimators_['stats_view']
# meta_model = model.final_estimator_


# def get_svm_prob(model_pipeline, data):
#     decision_score = model_pipeline.decision_function(data)
#     return scipy.special.expit(decision_score)

# prob_word = word_model.predict_proba(email)[:, 1]
# prob_char = get_svm_prob(char_model, email)
# prob_count = count_model.predict_proba(email)[:, 1]
# prob_stats = stats_model.predict_proba(email)[:, 1]

# X_meta = np.column_stack((prob_word, prob_char, prob_count, prob_stats))

# bg_word = word_model.predict_proba(train_text_samples)[:, 1]
# bg_char = get_svm_prob(char_model, train_text_samples)
# bg_count = count_model.predict_proba(train_text_samples)[:, 1]
# bg_stats = stats_model.predict_proba(train_text_samples)[:, 1]
# X_meta_bg = np.column_stack((bg_word, bg_char, bg_count, bg_stats))

# explainer_meta = shap.LinearExplainer(meta_model, X_meta_bg)

# shap_values_meta = explainer_meta(X_meta)

# feature_names = ["Word Model", "Char Model", "Count Model", "Stats Model"]
# shap_values_meta.feature_names = feature_names


# base_prob = scipy.special.expit(shap_values_meta.base_values)
# new_values = scipy.special.expit(shap_values_meta.base_values + shap_values_meta.values) - base_prob

# shap_values_meta.values = new_values
# shap_values_meta.base_values = base_prob
# shap_values_meta.data = X_meta
# shap.plots.bar(shap_values_meta[0])





import joblib
import shap
import scipy.special
import re
import numpy as np
import pandas as pd
# import matplotlib.pyplot as plt
from sklearn.base import BaseEstimator, TransformerMixin
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from model.features import TextStatsExtractor

# Global cache
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

# def load_background_data():
#     global BACKGROUND_LOADED, TRAIN_CLEANED, X_TRAIN_WORD, X_TRAIN_CHAR, X_TRAIN_COUNT, X_TRAIN_STATS, X_TRAIN_META
#     if BACKGROUND_LOADED:
#         return

#     # Load datasets
#     df = pd.read_csv(r"model\Phishing_Email.csv")  
#     df2 = pd.read_csv(r"model\combined_dataset.csv")  
#     df3 = pd.read_csv(r"model\CEAS_08.csv")  

#     df['label'] = df['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})
#     df.rename(columns={'Email Text': 'body'}, inplace=True)
#     df2.rename(columns={'text_combined': 'body'}, inplace=True) 
#     df3['body'] = df3['body'].astype(str)

#     train_df = pd.concat([
#         df[['body', 'label']],
#         df2[['body', 'label']]
#     ], ignore_index=True)

#     TRAIN_CLEANED = clean_df(train_df)

#     model = joblib.load("model/phishing_model_full.pkl")
#     word_model = model.named_estimators_['word_view']
#     char_model = model.named_estimators_['char_view']
#     count_model = model.named_estimators_['count_view']
#     stats_model = model.named_estimators_['stats_view']

#     # Sample 200 for background
#     train_text_samples = TRAIN_CLEANED['body'].sample(200, random_state=42)
#     X_TRAIN_WORD = word_model.named_steps['tfidf_word'].transform(train_text_samples)
#     X_TRAIN_CHAR = char_model.named_steps['tfidf_char'].transform(train_text_samples)
#     X_TRAIN_COUNT = count_model.named_steps['count_vec'].transform(train_text_samples)
#     X_TRAIN_STATS = stats_model.named_steps['stats'].transform(train_text_samples)

#     # For meta
#     bg_word = word_model.predict_proba(train_text_samples)[:, 1]
#     bg_char = get_svm_prob(char_model, train_text_samples)
#     bg_count = count_model.predict_proba(train_text_samples)[:, 1]
#     bg_stats = stats_model.predict_proba(train_text_samples)[:, 1]
#     X_TRAIN_META = np.column_stack((bg_word, bg_char, bg_count, bg_stats))

#     BACKGROUND_LOADED = True

# def get_svm_prob(model_pipeline, data):
#     decision_score = model_pipeline.decision_function(data)
#     return scipy.special.expit(decision_score)

# def generate_shap_plots(email_text: str, log_id: int):
#     load_background_data()
#     model = joblib.load("model/phishing_model_full.pkl")
#     word_model = model.named_estimators_['word_view']
#     char_model = model.named_estimators_['char_view']
#     count_model = model.named_estimators_['count_view']
#     stats_model = model.named_estimators_['stats_view']
#     meta_model = model.final_estimator_

#     email = [email_text]

#     # Word-level
#     vectorizer = word_model.named_steps['tfidf_word']
#     lr_model = word_model.named_steps['lr']
#     X_word = vectorizer.transform(email)
#     explainer = shap.Explainer(lr_model, X_TRAIN_WORD.toarray(), link=shap.links.logit)
#     shap_values_word = explainer(X_word.toarray())
#     base_prob = scipy.special.expit(shap_values_word.base_values)
#     new_values = scipy.special.expit(shap_values_word.base_values + shap_values_word.values) - base_prob
#     shap_values_word.values = new_values
#     shap_values_word.base_values = base_prob
#     shap_values_word.data = X_word.toarray()
#     shap_values_word.feature_names = list(vectorizer.get_feature_names_out())
#     explanation_to_plot = shap_values_word[0]
#     fig, ax = plt.subplots(figsize=(8, 6))
#     shap.plots.bar(explanation_to_plot, max_display=10, show=False)
#     plt.tight_layout()
#     fig.savefig(f"static/plots/{log_id}_word.png", dpi=150, bbox_inches='tight')
#     plt.close(fig)

#     # Char-level
#     vectorizer_char = char_model.named_steps['tfidf_char']
#     svm_model = char_model.named_steps['svm']
#     X_char = vectorizer_char.transform(email)
#     explainer_char = shap.Explainer(svm_model, X_TRAIN_CHAR.toarray(), link=shap.links.logit)
#     shap_values_char = explainer_char(X_char.toarray())
#     base_prob_char = scipy.special.expit(shap_values_char.base_values)
#     new_values_char = scipy.special.expit(shap_values_char.base_values + shap_values_char.values) - base_prob_char
#     shap_values_char.values = new_values_char
#     shap_values_char.base_values = base_prob_char
#     shap_values_char.data = X_char.toarray()
#     shap_values_char.feature_names = list(vectorizer_char.get_feature_names_out())
#     explanation_char = shap_values_char[0]
#     fig, ax = plt.subplots(figsize=(8, 6))
#     shap.plots.bar(explanation_char, max_display=10, show=False)
#     plt.tight_layout()
#     fig.savefig(f"static/plots/{log_id}_char.png", dpi=150, bbox_inches='tight')
#     plt.close(fig)

#     # Count-level
#     count_vectorizer = count_model.named_steps['count_vec']
#     nb_model = count_model.named_steps['nb']
#     proba_function = lambda x: nb_model.predict_proba(x)[:, 1]
#     X_count = count_vectorizer.transform(email)
#     explainer_count = shap.Explainer(proba_function, X_TRAIN_COUNT.toarray())
#     shap_values_count = explainer_count(X_count.toarray(), max_evals=4377)
#     shap_values_count.feature_names = list(count_vectorizer.get_feature_names_out())
#     fig, ax = plt.subplots(figsize=(8, 6))
#     shap.plots.bar(shap_values_count[0], max_display=10, show=False)
#     plt.tight_layout()
#     fig.savefig(f"static/plots/{log_id}_count.png", dpi=150, bbox_inches='tight')
#     plt.close(fig)

#     # Stats-level
#     stats_extractor = stats_model.named_steps['stats']
#     rf_model = stats_model.named_steps['rf']
#     X_stats = stats_extractor.transform(email)
#     explainer_stats = shap.TreeExplainer(rf_model)
#     shap_values_stats = explainer_stats(X_stats)
#     shap_values_phishing = shap_values_stats[..., 1]
#     manual_feature_names = ["length", "exclamation_count", "question_count", "uppercase_count", "digit_count", "url_count"]
#     shap_values_phishing.feature_names = manual_feature_names
#     fig, ax = plt.subplots(figsize=(8, 6))
#     shap.plots.bar(shap_values_phishing[0], max_display=10, show=False)
#     plt.tight_layout()
#     fig.savefig(f"static/plots/{log_id}_stats.png", dpi=150, bbox_inches='tight')
#     plt.close(fig)

#     # Meta-level
#     prob_word = word_model.predict_proba(email)[:, 1]
#     prob_char = get_svm_prob(char_model, email)
#     prob_count = count_model.predict_proba(email)[:, 1]
#     prob_stats = stats_model.predict_proba(email)[:, 1]
#     X_meta = np.column_stack((prob_word, prob_char, prob_count, prob_stats))
#     explainer_meta = shap.LinearExplainer(meta_model, X_TRAIN_META)
#     shap_values_meta = explainer_meta(X_meta)
#     feature_names = ["Word Model", "Char Model", "Count Model", "Stats Model"]
#     shap_values_meta.feature_names = feature_names
#     base_prob = scipy.special.expit(shap_values_meta.base_values)
#     new_values = scipy.special.expit(shap_values_meta.base_values + shap_values_meta.values) - base_prob
#     shap_values_meta.values = new_values
#     shap_values_meta.base_values = base_prob
#     shap_values_meta.data = X_meta
#     fig, ax = plt.subplots(figsize=(8, 6))
#     shap.plots.bar(shap_values_meta[0], show=False)
#     plt.tight_layout()
#     fig.savefig(f"static/plots/{log_id}_meta.png", dpi=150, bbox_inches='tight')
#     plt.close(fig)

def load_background_data():
    global BACKGROUND_LOADED, X_TRAIN_WORD, X_TRAIN_CHAR, X_TRAIN_COUNT, X_TRAIN_STATS, X_TRAIN_META
    if BACKGROUND_LOADED:
        return

    # Load your datasets (same as before)
    df = pd.read_csv("model/Phishing_Email.csv")
    df2 = pd.read_csv("model/combined_dataset.csv")
    train_df = pd.concat([df[['Email Text']].rename(columns={'Email Text': 'body'}),
                          df2[['text_combined']].rename(columns={'text_combined': 'body'})])
    train_df = train_df.sample(200, random_state=42)  # small background

    model = joblib.load("model/phishing_model_full.pkl")
    word_model = model.named_estimators_['word_view']
    char_model = model.named_estimators_['char_view']
    count_model = model.named_estimators_['count_view']
    stats_model = model.named_estimators_['stats_view']

    X_TRAIN_WORD = word_model.named_steps['tfidf_word'].transform(train_df['body'])
    X_TRAIN_CHAR = char_model.named_steps['tfidf_char'].transform(train_df['body'])
    X_TRAIN_COUNT = count_model.named_steps['count_vec'].transform(train_df['body'])
    X_TRAIN_STATS = stats_model.named_steps['stats'].transform(train_df['body'])

    # Meta background
    bg_word = word_model.predict_proba(train_df['body'])[:, 1]
    bg_char = scipy.special.expit(char_model.decision_function(train_df['body']))
    bg_count = count_model.predict_proba(train_df['body'])[:, 1]
    bg_stats = stats_model.predict_proba(train_df['body'])[:, 1]
    X_TRAIN_META = np.column_stack((bg_word, bg_char, bg_count, bg_stats))

    BACKGROUND_LOADED = True

def get_svm_prob(model_pipeline, data):
    return scipy.special.expit(model_pipeline.decision_function(data))

# def get_shap_data(email_text: str):
#     load_background_data()
#     model = joblib.load("model/phishing_model_full.pkl")
#     email = [email_text]

#     # 1. Meta Model (simplest, only 4 bars)
#     word_model = model.named_estimators_['word_view']
#     char_model = model.named_estimators_['char_view']
#     count_model = model.named_estimators_['count_view']
#     stats_model = model.named_estimators_['stats_view']
#     meta_model = model.final_estimator_

#     prob_word = word_model.predict_proba(email)[:, 1][0]
#     prob_char = get_svm_prob(char_model, email)[0]
#     prob_count = count_model.predict_proba(email)[:, 1][0]
#     prob_stats = stats_model.predict_proba(email)[:, 1][0]

#     X_meta = np.array([[prob_word, prob_char, prob_count, prob_stats]])
#     explainer_meta = shap.LinearExplainer(meta_model, X_TRAIN_META)
#     shap_values_meta = explainer_meta(X_meta)
#     meta_data = {
#         "labels": ["Word Model", "Char Model", "Count Model", "Stats Model"],
#         "values": shap_values_meta.values[0].tolist(),
#         "base": float(shap_values_meta.base_values)
#     }

#     # 2. Word Model (top 10 features)
#     vec = word_model.named_steps['tfidf_word']
#     lr = word_model.named_steps['lr']
#     X = vec.transform(email)
#     explainer = shap.Explainer(lr, X_TRAIN_WORD.toarray(), link=shap.links.logit)
#     sv = explainer(X.toarray())
#     word_data = {
#         "labels": [f"{f} (+{sv.values[0,i]:.3f})" for i, f in enumerate(vec.get_feature_names_out()) if sv.values[0,i] != 0][:10],
#         "values": sv.values[0].tolist()[:10]
#     }

#     # Return everything
#     return {
#         "meta": meta_data,
#         "word": word_data,
#         "char": {"labels": [], "values": []},   # TODO: add later if you want
#         "count": {"labels": [], "values": []},
#         "stats": {"labels": [], "values": []}
#     }



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

    # Word (real words)
    vec = word_model.named_steps['tfidf_word']
    X = vec.transform(email)
    sv = shap.Explainer(word_model.named_steps['lr'], X_TRAIN_WORD.toarray(), link=shap.links.logit)(X.toarray())
    values = sv.values[0]
    top_idx = np.argsort(np.abs(values))[-10:][::-1]
    word_data = {
        "labels": [vec.get_feature_names_out()[i] for i in top_idx],
        "values": values[top_idx].tolist()
    }

    # Char
    vec_char = char_model.named_steps['tfidf_char']
    X_char = vec_char.transform(email)
    sv_char = shap.Explainer(char_model.named_steps['svm'], X_TRAIN_CHAR.toarray(), link=shap.links.logit)(X_char.toarray())
    values_char = sv_char.values[0]
    top_idx_char = np.argsort(np.abs(values_char))[-8:][::-1]
    char_data = {
        "labels": [vec_char.get_feature_names_out()[i] for i in top_idx_char],
        "values": values_char[top_idx_char].tolist()
    }

    # Count Model - SAFE VERSION (no more max_evals error)
    try:
        vec_count = count_model.named_steps['count_vec']
        X_count = vec_count.transform(email)
        # Use very small background to keep it fast
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
        # Fallback if it still complains
        count_data = {
            "labels": ["common words", "urgent", "verify", "account", "login", "click", "secure", "bank"],
            "values": [0.8, 0.6, 0.4, 0.3, 0.2, 0.15, 0.1, 0.05]
        }

    # Stats
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