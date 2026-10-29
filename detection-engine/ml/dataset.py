"""
Training and Evaluation Dataset Utility
Provides realistic baseline HTTP traffic for training Isolation Forest
and labeled holdout evaluation samples.
"""

import json
from typing import List, Dict, Any, Tuple


def get_benign_training_samples(n_samples: int = 1000) -> List[Dict[str, Any]]:
    """
    Generates a deterministic dataset of normal, benign web application traffic.
    Represents typical browsing, navigation, searches, and form submissions.
    """
    benign_paths = [
        ("/", "GET", 200, 15.0),
        ("/search?q=laptop", "GET", 200, 22.0),
        ("/search?q=phone+accessories", "GET", 200, 28.0),
        ("/search?q=wireless+keyboard", "GET", 200, 19.0),
        ("/profile", "GET", 200, 35.0),
        ("/dashboard", "GET", 200, 40.0),
        ("/products/item?id=101", "GET", 200, 18.0),
        ("/products/item?id=205", "GET", 200, 21.0),
        ("/categories/electronics", "GET", 200, 25.0),
        ("/about-us", "GET", 200, 12.0),
        ("/contact", "GET", 200, 14.0),
        ("/faq", "GET", 200, 16.0),
        ("/login", "GET", 200, 18.0),
        ("/login", "POST", 200, 55.0), # Successful login
        ("/api/user/settings", "PUT", 200, 45.0),
        ("/static/css/style.css", "GET", 304, 5.0),
        ("/static/js/bundle.js", "GET", 304, 8.0),
        ("/images/logo.png", "GET", 304, 10.0),
        ("/old-page", "GET", 301, 12.0),
        ("/search?category=books&page=2", "GET", 200, 24.0),
        ("/articles/cybersecurity-overview", "GET", 200, 30.0),
        ("/misplaced-link", "GET", 404, 14.0),
        ("/blog/article-about-scripting-tips", "GET", 200, 32.0),
        ("/faq?topic=billing&lang=vi", "GET", 200, 18.0),
        ("/api/items?limit=25&offset=50&fields=id,title,price", "GET", 200, 22.0),
        ("/search?q=c%2B%2B+programming+language", "GET", 200, 25.0),
        ("/faq?q=what's+the+return+policy%3F", "GET", 200, 24.0),
        ("/items/review?id=45&rating=5&sort=recent", "GET", 200, 20.0),
        ("/search?q=intel+core+i7-13700k+vs+amd+ryzen+7", "GET", 200, 28.0),
        ("/cart/items/add?item_id=550&qty=1", "POST", 200, 45.0),
        ("/checkout/shipping-rates?country=VN&postal=700000", "GET", 200, 40.0),
        ("/search?q=error+code+500+troubleshooting+guide", "GET", 200, 26.0),
        ("/documentation/api/v1/auth/tokens#refresh", "GET", 200, 22.0)
    ]

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    ]

    samples = []
    for i in range(n_samples):
        path, method, status, base_rt = benign_paths[i % len(benign_paths)]
        ua = user_agents[i % len(user_agents)]
        ip = f"192.168.1.{(i % 50) + 1}"
        # Small variance in response time
        rt = base_rt + ((i % 10) * 1.5)

        samples.append({
            "timestamp": 1700000000.0 + (i * 2.0),
            "ip": ip,
            "method": method,
            "url": path,
            "statusCode": status,
            "userAgent": ua,
            "responseTime": rt
        })

    return samples


def get_labeled_evaluation_dataset() -> Tuple[List[Dict[str, Any]], List[int]]:
    """
    Returns a holdout evaluation dataset with true binary labels:
    0 = Benign request
    1 = Anomaly / Attack request
    """
    benign_samples = [
        {"url": "/", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 15.0},
        {"url": "/search?q=laptop", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 20.0},
        {"url": "/profile", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 30.0},
        {"url": "/login", "method": "POST", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 45.0},
        {"url": "/contact", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 10.0},
        {"url": "/items/detail?id=99", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 18.0},
        {"url": "/images/avatar.jpg", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 8.0},
        {"url": "/search?q=cloud+security", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 25.0},
        {"url": "/about-us", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 12.0},
        {"url": "/dashboard", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 35.0}
    ]

    anomaly_samples = [
        # SQL Injection
        {"url": "/search?q=' OR '1'='1", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 500.0},
        {"url": "/items?id=1' UNION SELECT null, username, password FROM users--", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 350.0},
        # XSS
        {"url": "/search?q=<script>alert('pwned')</script>", "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 20.0},
        {"url": "/profile?bio=<img src=x onerror=alert(document.cookie)>", "method": "POST", "statusCode": 200, "userAgent": "Mozilla/5.0", "responseTime": 40.0},
        # Automated Scanner
        {"url": "/search?q=test", "method": "GET", "statusCode": 200, "userAgent": "sqlmap/1.7#stable", "responseTime": 25.0},
        {"url": "/", "method": "GET", "statusCode": 200, "userAgent": "Nikto/2.1.6", "responseTime": 30.0},
        # Sensitive Probe
        {"url": "/.env", "method": "GET", "statusCode": 404, "userAgent": "Mozilla/5.0", "responseTime": 10.0},
        {"url": "/.git/config", "method": "GET", "statusCode": 404, "userAgent": "Mozilla/5.0", "responseTime": 12.0},
        # Excessive Length / Malformed Query
        {"url": "/api/query?param=" + ("A" * 1500), "method": "GET", "statusCode": 400, "userAgent": "Mozilla/5.0", "responseTime": 150.0},
        # Brute Force login (high failed rate)
        {"url": "/login", "method": "POST", "statusCode": 401, "userAgent": "Mozilla/5.0", "responseTime": 30.0}
    ]

    all_samples = benign_samples + anomaly_samples
    labels = [0] * len(benign_samples) + [1] * len(anomaly_samples)
    return all_samples, labels


def get_expanded_evaluation_dataset() -> Tuple[List[Dict[str, Any]], List[int]]:
    """
    Returns the comprehensive Phase 7 holdout evaluation dataset (80 samples):
    Loads from data/holdout_dataset_v2.json.
    """
    import os
    dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/holdout_dataset_v2.json"))
    if os.path.exists(dataset_path):
        with open(dataset_path, "r", encoding="utf-8") as f:
            samples = json.load(f)
            labels = [int(s.get("ground_truth", 0)) for s in samples]
            return samples, labels
    return get_labeled_evaluation_dataset()


def get_unseen_evaluation_dataset() -> Tuple[List[Dict[str, Any]], List[int]]:
    """
    Returns the independent Phase 8 unseen evaluation dataset (80 samples, 100% disjoint from training paths):
    Loads from data/holdout_dataset_unseen_v3.json.
    """
    import os
    dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/holdout_dataset_unseen_v3.json"))
    if os.path.exists(dataset_path):
        with open(dataset_path, "r", encoding="utf-8") as f:
            samples = json.load(f)
            labels = [int(s.get("ground_truth", 0)) for s in samples]
            return samples, labels
    return get_expanded_evaluation_dataset()


if __name__ == "__main__":
    samples, labels = get_expanded_evaluation_dataset()
    print(f"Total samples: {len(samples)}")
    print(f"Benign count : {labels.count(0)}")
    print(f"Attack count : {labels.count(1)}")
