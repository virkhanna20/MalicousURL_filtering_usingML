from flask import Flask, render_template, request
import pickle
import numpy as np
from urllib.parse import urlparse
from tld import get_tld
from cybermodel import having_ip_address,abnormal_url,count_dot,count_www,count_atrate,no_of_dir,no_of_embed,shortening_service,count_https,count_http,count_per,count_ques,count_hyphen,count_equal,url_length,hostname_length,suspicious_words,digit_count,letter_count,fd_length,tld_length
app = Flask(__name__)

# Load the model from the binary file
with open('test', 'rb') as f:
    model = pickle.load(f)

# Function to extract features from URL and make prediction
def get_prediction_from_url(url):
    # Function to extract features and make prediction
    def main(url):
        status = []
        status.append(having_ip_address(url))
        status.append(abnormal_url(url))
        status.append(count_dot(url))
        status.append(count_www(url))
        status.append(count_atrate(url))
        status.append(no_of_dir(url))
        status.append(no_of_embed(url))
        status.append(shortening_service(url))
        status.append(count_https(url))
        status.append(count_http(url))
        status.append(count_per(url))
        status.append(count_ques(url))
        status.append(count_hyphen(url))
        status.append(count_equal(url))
        status.append(url_length(url))
        status.append(hostname_length(url))
        status.append(suspicious_words(url))
        status.append(digit_count(url))
        status.append(letter_count(url))
        status.append(fd_length(url))
        tld = get_tld(url, fail_silently=True)
        status.append(tld_length(tld))
        return status

    features_test = main(url)
    # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))
    pred = model.predict(features_test)
    if pred == 0:
        return "SAFE"
    elif pred == 1:
        return "DEFACEMENT"
    elif pred == 2:
        return "PHISHING"
    elif pred == 3:
        return "MALWARE"

@app.route('/')
def index():
    return render_template('final_homepage.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    prediction = get_prediction_from_url(url)
    return render_template('final_homepage.html', prediction=prediction)

if __name__ == '__main__':
    app.run(debug=True)
