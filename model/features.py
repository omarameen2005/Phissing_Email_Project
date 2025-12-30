import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

class TextStatsExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        data = []
        for text in X:
            text = str(text)
            l = len(text)
            
            row = [
                l,                                    
                text.count('!'),                        
                text.count('?'),                        
                sum(1 for c in text if c.isupper()),    
                sum(1 for c in text if c.isdigit()),    
                text.count('http'),                   
            ]
            data.append(row)
        return np.array(data)