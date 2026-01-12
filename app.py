from flask import Flask, request, render_template
from heuristics.url_heuristics import url_risk_score
from threat_intelligence.threat_lookup import check_threat

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    verdict = None
    risk = None
    url = None

    if request.method == "POST":
        url = request.form["url"].strip()

        # 1) Known phishing lookup
        if check_threat(url):
            verdict = "PHISHING"
            risk = 100

        # 2) Heuristic detection
        else:
            risk = url_risk_score(url)

            if risk <= 30:
                verdict = "SAFE"
            elif risk <= 60:
                verdict = "SUSPICIOUS"
            else:
                verdict = "PHISHING"

    return render_template("index.html", verdict=verdict, risk=risk, url=url)

if __name__ == "__main__":
    app.run(debug=True)
