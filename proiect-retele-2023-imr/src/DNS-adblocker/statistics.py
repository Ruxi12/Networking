import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
from flask import Flask, render_template
from collections import Counter

app = Flask(__name__)

def count_domains(domains):
    # Count occurrences of 'facebook' and 'google'
    facebook_count = sum('facebook' in domain for domain in domains)
    google_count = sum('google' in domain for domain in domains)

    # Count occurrences of all domains
    domain_counts = Counter(domains)

    # Find the top 10 domains
    top_10_domains = domain_counts.most_common(10)

    return facebook_count, google_count, top_10_domains

def create_bar_chart(domains):
    domain_names = [domain[0] for domain in domains]
    domain_counts = [domain[1] for domain in domains]

    plt.bar(domain_names, domain_counts)
    plt.xlabel('Domains')
    plt.ylabel('Count')
    plt.title('Top 10 Domains')
    plt.xticks(rotation=45)
    plt.tick_params(axis='x', labelsize=2)  # Set the font size for x-axis labels
    plt.tight_layout()

    # Save the chart as an image file
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_data = base64.b64encode(buffer.getvalue()).decode('utf-8')

    plt.close()  # Close the figure to release resources

    return image_data

@app.route('/')
def index():
    with open('domains.txt', 'r') as file:
        domains = file.read().splitlines()

    facebook_count, google_count, top_10_domains = count_domains(domains)

    chart_image = create_bar_chart(top_10_domains)

    return render_template('index.html', facebook_count=facebook_count, google_count=google_count, top_10_domains=top_10_domains, chart_image=chart_image)

if __name__ == '__main__':
    app.run(debug=True)
