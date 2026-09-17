# Contributing to SubZero 🤝

Thank you for your interest in contributing to **SubZero**! We welcome bug reports, feature suggestions, new OSINT source integrations, and code contributions from the global security community.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) and [Security Policy](SECURITY.md) before participating.

---

## 🛠️ Development Setup

### 1. Fork & Clone
```bash
# Clone your fork
git clone https://github.com/<your-username>/subdomain_finder_pro.git
cd subdomain_finder_pro
git remote add upstream https://github.com/haafizkhushbuddin1-blip/subdomain_finder_pro.git
git checkout -b feature/my-new-feature
```

### 2. Environment Setup
We recommend using [uv](https://github.com/astral-sh/uv) or standard Python 3.10+:

```bash
# Using uv (Recommended for ultra-fast setup):
uv run python app.py

# Or using standard venv:
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### 3. Install Discovery Binaries (Optional)
Run the automated tool installer to grab precompiled Subfinder and Amass binaries:
```bash
python install_tools.py
```

---

## 🧪 Running Unit & Integration Tests

Always ensure the entire test suite passes before submitting a pull request:
```bash
pytest tests/
# or with uv:
uv run --with-requirements requirements.txt --with pytest pytest tests/
```
All tests must pass with 100% green status.

---

## 🚀 Adding a New OSINT Provider

To add a new passive OSINT source:
1. Open [`enumerator/providers.py`](enumerator/providers.py).
2. Implement your provider function following the decoupled signature:
   ```python
   def my_provider(domain: str) -> tuple[list[str], str | None, int]:
       """
       Queries the API or service.
       Returns: (subdomains_list, error_notice_or_None, total_count)
       """
   ```
3. Register your function in the `PROVIDERS` dictionary.
4. Add a unit test in [`tests/test_requirements.py`](tests/test_requirements.py).

---

## 📐 Code Guidelines & Architecture Rules

- **Zero Paint / GPU Lag**: Do not introduce continuous canvas physics or heavy CSS Gaussian blur filters (`filter: blur(>20px)`) that peg low-spec GPUs.
- **Strict Decoupling**: Keep active DNS discovery decoupled from live HTTP probing.
- **Thread Safety**: Always use locks (`threading.RLock`) when modifying shared scan or batch state.
- **Clean REST APIs**: Endpoints should return clean data payloads. Project metadata belongs in `/api/info`.

---

## 🏆 Attribution & Recognition

SubZero was created and is led by **Gulam Khan**. 

- Core copyright and project ownership remain under the [MIT License](LICENSE) by Gulam Khan.
- We believe in celebrating everyone who contributes! Once your pull request is merged, you are invited to add your name, GitHub handle, and contribution description to [`CONTRIBUTORS.md`](CONTRIBUTORS.md).

---

## 📄 Licensing

By contributing to SubZero, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

