# Guilty Spark: API URL Path Prediction and Fuzzing Tool

Guilty Spark is an advanced command-line tool designed for penetration testers and security researchers (with proper authorization) to discover hidden API endpoints. It leverages probabilistic modeling techniques—specifically Markov chains with Laplace smoothing—to generate candidate endpoints based on known API patterns. Additionally, Guilty spark can augment its candidate pool with fuzzing techniques using Radamsa. The tool also supports appending static URL query parameters to every request and presents its output in a visually appealing, color-coded format.

---

## Table of Contents

- [Purpose and Use Cases](#purpose-and-use-cases)
- [Features](#features)
- [How to Use Guilty Spark](#how-to-use-guilty-spark)
  - [Command-Line Arguments](#command-line-arguments)
  - [Usage Examples](#usage-examples)
- [Mathematical Notation](#mathematical-notation)
  - [Endpoint Representation](#endpoint-representation)
  - [Markov Chain Modeling](#markov-chain-modeling)
  - [Laplace Smoothing](#laplace-smoothing)
  - [Candidate Endpoint Probability](#candidate-endpoint-probability)
- [Installation and Dependencies](#installation-and-dependencies)
- [License](#license)
- [Contributing](#contributing)

---

## Purpose and Use Cases

Guilty Spark is built to help identify potentially undisclosed API endpoints by:

- **Learning from Known Endpoints:**
  Guilty Spark tokenizes and normalizes a given list of API endpoints, then builds a Markov chain model to capture the underlying structure.

- **Predicting New Endpoints:**
  The tool uses the Markov chain to predict likely subsequent tokens and generate candidate endpoints.

- **Assigning Probabilities:**
  With Laplace smoothing applied, Guilty Spark calculates the probability of each candidate endpoint, ensuring that even unseen transitions have a non-zero probability.

- **Optional Fuzzing:**
  When enabled, Guilty Spark utilizes Radamsa to fuzz candidate endpoints, thereby generating additional variants for testing.

- **Validation:**
  Guilty Spark validates each candidate by sending HTTP requests (with optional static query parameters) and displays the results with color-coded output.

---

## Features

- **Dynamic Input:**
  Accepts known endpoints and common words via JSON files or inline comma-separated lists.

- **Configurable Threshold:**
  Filters candidate endpoints based on a user-defined probability threshold.

- **Static Query Parameters:**
  Supports appending static URL query parameters to every request.

- **Throttling:**
  Configurable delay between HTTP requests to avoid overwhelming target systems.

- **Colorful Output:**
  Uses color-coded terminal output (green for valid endpoints, red for invalid ones).

- **Optional Fuzzing:**
  Integrates Radamsa to fuzz candidate endpoints when enabled.

---

## How to Use Guilty Spark

### Command-Line Arguments

- **`--target`**
  The base URL of the API.
  _Example:_ `--target "https://something.com"`

- **`--eplist`**
  File path to a JSON file containing a list of known endpoints.
  _Example:_ `--eplist endpoints.json`

- **`--eps`**
  Inline comma-separated list of known endpoints.
  _Example:_ `--eps "/api/v1/users, /api/v1/products, /api/v1/orders"`

- **`--wordfile`**
  File path to a JSON file containing a list of common words used for extending endpoints.
  _Example:_ `--wordfile words.json`

- **`--words`**
  Inline comma-separated list of common words.
  _Example:_ `--words "admin,login,logout,register,config"`

- **`--static-pattern`**
  Static URL query parameters to be appended to every request.
  _Example:_ `--static-pattern "?api_key=yourkey"`

- **`--fuzz`**
  Enable fuzzing mode using Radamsa. When enabled, Guilty spark will generate additional candidate endpoints via fuzzing.

- **`--iters`**
  Number of iterations for fuzzing (only used if `--fuzz` is enabled).
  _Example:_ `--iters 10`

- **`--throttle`**
  Throttle time in seconds between HTTP requests.
  _Example:_ `--throttle 0.5`

- **`--threshold`**
  Probability threshold for candidate filtering.
  _Example:_ `--threshold 0.001` (default is 0.001)

If no arguments are provided or if the `-h` flag is used, Guilty Spark displays a detailed help message with usage instructions.

### Usage Examples

**Example 1: Using JSON files for endpoints and common words with fuzzing enabled**

```bash
python3 spark.py --target "https://something.com" --eplist endpoints.json --wordfile words.json --fuzz --iters 10 --throttle 0.5 --static-pattern "?api_key=yourkey" --threshold 0.001
```

**Example 2: Using inline comma-separated lists**

```bash
python3 spark.py --target "https://something.com" --eps "/api/v1/users, /api/v1/products, /api/v1/orders" --words "admin,login,logout,register,config" --static-pattern "?api_key=yourkey" --throttle 0.25 --threshold 0.001
```

# Mathematical Notation

Guilty Spark's prediction and filtering methodologies are based on the following mathematical concepts:

## Endpoint Representation

Let $\( E = \{e_1, e_2, \dots, e_N\} \)$ be a set of known endpoints, where each endpoint is represented as a sequence of tokens:


$e = (t_1, t_2, \dots, t_n)$

After tokenization, each endpoint is padded with special tokens:


$e' = (\langle \text{START} \rangle, \langle \text{START} \rangle, t_1, t_2, \dots, t_n, \langle \text{END} \rangle)$

## Markov Chain Modeling

For an order-2 Markov chain, the probability of an endpoint is approximated by:

$P(e) \approx \prod_{i=1}^{n} P(t_i \mid t_{i-2}, t_{i-1})$

## Laplace Smoothing

To compute each transition probability, Laplace smoothing is applied as follows:

$P(t_i \mid t_{i-2}, t_{i-1}) = \frac{C(t_{i-2}, t_{i-1}, t_i) + \alpha}{C(t_{i-2}, t_{i-1}) + \alpha \cdot V}$

where:

- $\( C(t_{i-2}, t_{i-1}, t_i) \)$ is the count of the sequence $\((t_{i-2}, t_{i-1}, t_i)\)$ in the training data.
- $\( C(t_{i-2}, t_{i-1}) \)$ is the count of the sequence $\((t_{i-2}, t_{i-1})\)$.
- $\( V \)$ is the vocabulary size (i.e., the number of unique tokens).
- $\( \alpha \)$ is the Laplace smoothing constant (default value is 1.0).

## Candidate Endpoint Probability

The probability of a candidate endpoint \( c \) is computed as:

$P(c) = \prod_{i=1}^{m+1} P(t_i \mid t_{i-2}, t_{i-1})$

where the candidate \( c \) is tokenized and padded as:

$c = (\langle \text{START} \rangle, \langle \text{START} \rangle, t_1, t_2, \dots, t_m, \langle \text{END} \rangle)$

## Installation and Dependencies

Guilty Spark requires Python 3 and the following packages:

- `requests`
- `argparse`
- `colorama`

Install the necessary packages using pip:

```bash
pip install requests colorama
```

Additionally, Guilty spark uses Radamsa for fuzzing. Please ensure Radamsa is installed and available in your system's PATH.

## License

Guilty Spark is provided for authorized penetration testing and security research purposes only. Please ensure you have proper permission before using this tool on any target system. Use at your own risk.

Apache 2.0

## Contributing

Contributions, bug fixes, and enhancements are welcome! Please open an issue or submit a pull request on the project's repository.

Enjoy using Guilty Spark for your API endpoint discovery and fuzzing tasks! If you have any questions or suggestions, feel free to reach out.
