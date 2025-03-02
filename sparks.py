import re, json, time, sys, requests, subprocess, argparse
from collections import defaultdict, Counter
from colorama import init, Fore, Style

# Initialize colorama for colored terminal output.
init(autoreset=True)

# --- Utility Functions ---

def tokenize(endpoint):
    """Splits an endpoint string into tokens."""
    return [token for token in endpoint.strip("/").split("/") if token]

def normalize_token(token):
    """Normalizes tokens, replacing numbers and UUID-like strings."""
    if re.fullmatch(r'\d+', token):
        return "<id>"
    if re.fullmatch(r'[a-f0-9\-]{36}', token):
        return "<uuid>"
    return token

def extract_normalized_tokens(endpoints):
    """Tokenizes and normalizes a list of endpoints."""
    tokens_list = [tokenize(ep) for ep in endpoints]
    return [[normalize_token(token) for token in tokens] for tokens in tokens_list]

def build_markov_chain(token_sequences, order=2):
    """Builds a Markov chain (dictionary of Counters) from tokenized sequences."""
    markov_chain = defaultdict(Counter)
    for tokens in token_sequences:
        tokens = ["<START>"] * order + tokens + ["<END>"]
        for i in range(len(tokens) - order):
            key = tuple(tokens[i:i+order])
            next_token = tokens[i+order]
            markov_chain[key][next_token] += 1
    return markov_chain

def predict_next_tokens(chain, current_tokens, top_n=3):
    """Predicts the next token given the current state."""
    key = tuple(current_tokens)
    if key in chain:
        return chain[key].most_common(top_n)
    return []

def generate_candidates(token_sequences, chain, common_words, order=2):
    """
    Generates candidate endpoints using the Markov chain.
    If the chain predicts <END>, extends the path with common_words.
    """
    candidates = set()
    for tokens in token_sequences:
        for i in range(len(tokens)):
            current_state = tokens[max(0, i - order + 1):i+1]
            predictions = predict_next_tokens(chain, current_state)
            for token, _ in predictions:
                if token == "<END>":
                    for word in common_words:
                        candidate = "/" + "/".join(tokens[:i+1] + [word])
                        candidates.add(candidate)
                else:
                    candidate = "/" + "/".join(tokens[:i+1] + [token])
                    candidates.add(candidate)
    return candidates

def candidate_probability(candidate, chain, order=2, vocab_size=None, alpha=1.0):
    """
    Calculates the probability of a candidate endpoint using Laplace smoothing.
    
    P(next_token | state) = (count(state, next_token) + alpha) / (total(state) + alpha * V)
    """
    tokens = tokenize(candidate)
    tokens = ["<START>"] * order + tokens + ["<END>"]
    prob = 1.0

    if vocab_size is None:
        vocab = set()
        for counter in chain.values():
            vocab |= set(counter.keys())
        vocab_size = len(vocab)
    
    for i in range(order, len(tokens)):
        key = tuple(tokens[i-order:i])
        next_token = tokens[i]
        count_next = chain[key][next_token]
        total_count = sum(chain[key].values())
        prob *= (count_next + alpha) / (total_count + alpha * vocab_size)
    return prob

def validate_candidate(base_url, candidate, static_pattern="", timeout=5):
    """
    Validates a candidate endpoint by sending an HTTP GET request.
    Appends the static query parameters to the URL.
    Considers an endpoint valid if it returns status 200, 401, or 403.
    """
    url = base_url.rstrip("/") + candidate + static_pattern
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code in [200, 401, 403]:
            return True, response.status_code
        else:
            return False, response.status_code
    except Exception:
        return False, None

def fuzz_candidate(candidate, iterations=5):
    """
    Uses Radamsa to fuzz a candidate endpoint.
    Pipes the candidate to Radamsa via stdin and decodes its output.
    """
    fuzzed_candidates = set()
    for _ in range(iterations):
        try:
            process = subprocess.Popen(
                ['radamsa'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = process.communicate(input=candidate.encode('utf-8'))
            fuzzed_candidate = output.decode('utf-8', errors='replace').strip()
            if not fuzzed_candidate.startswith('/'):
                fuzzed_candidate = '/' + fuzzed_candidate
            fuzzed_candidates.add(fuzzed_candidate)
        except Exception:
            continue
    return list(fuzzed_candidates)

# --- Main Program ---

def main():
    parser = argparse.ArgumentParser(
        description="Oracle: API URL Path Prediction and Fuzzing Tool\n\n"
                    "Usage examples:\n"
                    "  python oracle.py --target \"https://something.com\" --eplist endpoints.json --wordfile words.json --fuzz --iters 10 --throttle 0.5 --static-pattern \"?api_key=yourkey\" --threshold 0.001\n"
                    "  python oracle.py --target \"https://something.com\" --eps \"/api/v1/users, /api/v1/products, /api/v1/orders\" --words \"admin,login,logout,register,config\" --static-pattern \"?api_key=yourkey\" --throttle 0.25 --threshold 0.001\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--target', required=True, help='Target base URL (e.g., "https://something.com")')
    
    # Known endpoints input: either JSON file or inline comma-separated list.
    parser.add_argument('--eplist', help='File path to JSON list of known endpoints')
    parser.add_argument('--eps', help='Inline comma-separated list of known endpoints')
    
    # Common words input: either JSON file or inline comma-separated list.
    parser.add_argument('--wordfile', help='File path to JSON list of common words')
    parser.add_argument('--words', help='Inline comma-separated list of common words')
    
    # Fuzzing mode.
    parser.add_argument('--fuzz', action='store_true', help='Enable fuzzing mode using Radamsa')
    parser.add_argument('--iters', type=int, default=5, help='Number of iterations for fuzzing (only used with --fuzz)')
    
    # Throttle: sleep time between HTTP requests (in seconds).
    parser.add_argument('--throttle', type=float, default=0.5, help='Throttle time in seconds between requests (default 0.5)')
    
    # Static URL query parameters.
    parser.add_argument('--static-pattern', default="", help='Static URL query parameters (e.g., "?api_key=yourkey")')
    
    # Probability threshold for candidate filtering.
    parser.add_argument('--threshold', type=float, default=0.001, help='Probability threshold for candidate filtering (default 0.001)')
    
    # If no arguments are provided, print help and exit.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
        
    args = parser.parse_args()
    
    base_url = args.target
    
    # Load known endpoints.
    if args.eplist:
        try:
            with open(args.eplist, 'r') as f:
                known_endpoints = json.load(f)
        except Exception as e:
            print(Fore.RED + f"Error reading endpoints JSON file: {e}")
            exit(1)
    elif args.eps:
        known_endpoints = [ep.strip() for ep in args.eps.split(",") if ep.strip()]
    else:
        print(Fore.RED + "No known endpoints provided. Use --eplist or --eps.")
        exit(1)
    
    # Load common words.
    default_common_words = [
        "admin", "login", "logout", "register", "config", "settings", "profile", "dashboard",
        "account", "users", "products", "orders", "reports", "data", "info", "create", "update",
        "delete", "search", "list", "detail", "status", "metrics", "stats", "analytics", "session",
        "token", "verify", "reset", "password", "security", "permissions", "roles", "notifications",
        "events", "logs", "history", "backup", "export", "import", "sync", "validate", "preferences",
        "categories", "items", "cart", "checkout", "payment", "invoice", "shipping", "tracking",
        "review", "rating", "feedback", "customer", "support", "help", "contact", "faq", "terms",
        "privacy", "policy", "subscription", "plan", "trial", "upgrade", "downgrade", "usage",
        "limits", "quota", "billing", "receipt", "refund", "order-history", "wishlist",
        "favorites", "recommendations", "offer", "coupon", "discount", "loyalty", "points", "gift",
        "voucher", "promotion", "news", "updates", "blog", "article", "announcement", "message",
        "chat", "forum", "community", "group", "team", "project", "task", "milestone",
        "calendar", "event", "schedule", "appointment", "reservation", "booking", "ticket",
        "incident", "alert", "emergency", "priority", "escalation", "assignment", "resource",
        "inventory", "warehouse", "supply", "demand", "forecast", "performance", "control",
        "panel", "manage", "manager", "automation", "integration", "connector", "api",
        "version", "v1", "v2", "public", "private", "internal", "external", "development", "staging",
        "production", "test", "debug", "configurations", "properties", "locale", "language", "timezone",
        "region", "country", "city", "district", "neighborhood", "address", "location", "coordinates",
        "map", "geocode", "find", "lookup", "reporting", "insights", "statistics", "graph",
        "chart", "trend",
        "document", "documents", "doc", "docs", "manual", "manuals", "guide", "guides",
        "tutorial", "tutorials", "whitepaper", "whitepapers", "academic", "academics",
        "journal", "journals", "articles", "paper", "papers", "publication", "publications",
        "book", "books", "library", "libraries", "thesis", "dissertation", "dissertations",
        "research", "study", "studies", "archive", "archives", "catalog", "catalogue",
        "reference", "references", "index", "indexes", "bibliography", "bibliographies",
        "handbook", "handbooks", "notes", "reviews", "analyses", "case-study", "case-studies",
        "overview", "summary", "abstract", "abstracts", "edition", "editions", "volume", "volumes",
        "periodical", "periodicals", "magazine", "magazines", "series", "encyclopedia",
        "encyclopedias", "compendium", "compendiums", "repository", "repositories", "database",
        "databases", "metadata", "curation", "curated", "collection", "collections", "compilation",
        "compilations", "shelf", "shelves", "cataloging", "cataloguing", "indexing", "monograph",
        "monographs", "treatise", "treatises", "discourse", "excerpts", "extracts", "manuscript",
        "manuscripts", "transcript", "transcripts", "dossier", "dossiers"
    ]
    common_words = default_common_words[:]
    if args.wordfile:
        try:
            with open(args.wordfile, 'r') as f:
                common_words = json.load(f)
        except Exception as e:
            print(Fore.RED + f"Error reading common words JSON file: {e}")
            exit(1)
    elif args.words:
        common_words = [w.strip() for w in args.words.split(",") if w.strip()]
    
    # Other parameters.
    throttle = args.throttle  # in seconds
    fuzz_enabled = args.fuzz
    fuzz_iterations = args.iters if fuzz_enabled else 0
    static_pattern = args.static_pattern  # e.g., "?api_key=yourkey"
    threshold_probability = args.threshold  # probability threshold for candidate filtering
    
    # --- Pipeline Execution ---
    
    # 1. Tokenize and normalize known endpoints.
    token_sequences = extract_normalized_tokens(known_endpoints)
    
    # 2. Build the Markov chain model (order-2).
    chain = build_markov_chain(token_sequences, order=2)
    
    # Compute global vocabulary size for smoothing.
    global_vocab = set()
    for counter in chain.values():
        global_vocab |= set(counter.keys())
    vocab_size = len(global_vocab)
    
    # 3. Generate candidate endpoints using Markov predictions and common words.
    candidates = generate_candidates(token_sequences, chain, common_words, order=2)
    
    # 4. If fuzzing is enabled and candidate pool is small, augment using fuzzing.
    if fuzz_enabled and len(candidates) < 10:
        additional_candidates = set()
        for candidate in list(candidates):
            fuzzed = fuzz_candidate(candidate, iterations=fuzz_iterations)
            additional_candidates.update(fuzzed)
        candidates.update(additional_candidates)
    
    # 5. Compute probability scores for each candidate using Laplace smoothing.
    scored_candidates = []
    for candidate in candidates:
        prob = candidate_probability(candidate, chain, order=2, vocab_size=vocab_size, alpha=1.0)
        if prob >= threshold_probability:
            scored_candidates.append((candidate, prob))
    
    # Sort candidates by probability (highest first).
    scored_candidates.sort(key=lambda x: x[1], reverse=True)
    
    print(Fore.CYAN + Style.BRIGHT + "Candidate Endpoints with Probability Scores:")
    for candidate, prob in scored_candidates:
        print(Fore.CYAN + f"{candidate}: {prob:.6f}")
    
    # 6. Validate candidates by sending HTTP GET requests.
    print("\n" + Fore.MAGENTA + Style.BRIGHT + "Validating Candidate Endpoints:")
    for candidate, prob in scored_candidates:
        is_valid, status = validate_candidate(base_url, candidate, static_pattern=static_pattern)
        if is_valid:
            print(Fore.GREEN + f"Valid endpoint: {candidate} (Status: {status}, Probability: {prob:.6f})")
        else:
            print(Fore.RED + f"Invalid endpoint: {candidate} (Status: {status}, Probability: {prob:.6f})")
        time.sleep(throttle)  # Throttle between requests

if __name__ == '__main__':
    main()

