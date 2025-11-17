# gemini_ai.py
import os
import time
from dotenv import load_dotenv

# keep compatibility with either "google.generativeai" or the newer "google.genai" packages
try:
    import google.generativeai as genai  # older package name
except Exception:
    try:
        # newer unified SDK
        from google import genai as genai_client
        genai = genai_client
    except Exception:
        genai = None

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY not set in environment")

# configure once
if hasattr(genai, "configure"):
    genai.configure(api_key=GEMINI_API_KEY)
elif hasattr(genai, "Client"):
    # new style client: we'll create client where needed
    client = genai.Client(api_key=GEMINI_API_KEY)
else:
    raise RuntimeError("Unsupported google genai package detected. Install google-generativeai or google-genai.")

SYSTEM_INSTRUCTION = """
You are Hackspeak, a friendly and knowledgeable cybersecurity assistant.
- Speak like a human.
- Keep responses short, clear, and helpful.
- Avoid overly technical or long-winded explanations unless asked.
- If the user asks "how this tool works", explain about that tool.
- If the question is vague, ask the user to clarify.
- Act like a companion, not a textbook.
"""

# Candidate models to try if listing is not available or returns nothing.
COMMON_MODEL_CANDIDATES = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
    "gemini-pro",
    "gemini-2.5"
]

def _list_models_from_sdk():
    """
    Try to list models using the installed SDK.
    Returns a list of model name strings or [] if listing isn't possible.
    """
    try:
        # older google.generativeai exposes genai.list_models()
        if hasattr(genai, "list_models"):
            # genai.list_models() may be a generator
            models = []
            for m in genai.list_models():
                # object might be a dict-like or object with 'name'
                name = getattr(m, "name", None) or m.get("name") if isinstance(m, dict) else None
                if name:
                    models.append(name)
            return models
        # newer client API: genai.Client().models.list() or client.models.list()
        if 'client' in globals() and hasattr(client, "models") and hasattr(client.models, "list"):
            models = []
            for m in client.models.list():
                name = getattr(m, "name", None) or m.get("name") if isinstance(m, dict) else None
                if name:
                    models.append(name)
            return models
    except Exception:
        # non-fatal; fall back to common candidates
        return []
    return []

def _pick_working_model():
    """
    Attempt to choose a model that works for chat by:
      1) trying to list models and pick a recent one, or
      2) falling back to a list of common candidates and trying each until one works.
    Returns (model_name, model_obj) on success, or (None, None) on failure.
    """
    candidates = []

    # 1) try SDK listing
    listed = _list_models_from_sdk()
    if listed:
        # prefer models that look like 2.x first
        listed_sorted = sorted(listed, key=lambda s: (not s.startswith("gemini-2"), s))
        candidates.extend(listed_sorted)

    # 2) append our common fallback candidates (de-duplicated)
    for c in COMMON_MODEL_CANDIDATES:
        if c not in candidates:
            candidates.append(c)

    # try each candidate by attempting to construct a GenerativeModel and start a chat
    for name in candidates:
        try:
            # create model object
            # older package signature:
            if hasattr(genai, "GenerativeModel"):
                # Some packages use model_name kw, some use plain string param
                try:
                    model = genai.GenerativeModel(model_name=name)
                except TypeError:
                    model = genai.GenerativeModel(name)
            else:
                # new client path: client.models.* (wrap in a simple generate_content check instead)
                if 'client' in globals():
                    # quick lightweight check: call generate_content with an extremely short test prompt.
                    # This DOES perform a network call, but it's fast and confirms permissions.
                    resp = client.models.generate_content(model=name, contents="hi")
                    # if no exception, we have a working model; create a minimal wrapper object
                    class SimpleModelWrapper:
                        def __init__(self, model_name):
                            self.model_name = model_name
                        def start_chat(self, history=None):
                            raise NotImplementedError("start_chat not implemented for client wrapper")
                    return (name, None)  # model object isn't used in this code path
                else:
                    continue

            # try to start a chat (this often fails quickly if model not available or not permitted)
            try:
                # seed the system instruction as an initial message in history.
                history = [
                    {"role": "user", "parts": [SYSTEM_INSTRUCTION.strip()]}
                ]
                chat = model.start_chat(history=history)
                # if we got a chat object, we can return it
                return (name, (model, chat))
            except Exception as e_chat:
                # starting chat may fail if model doesn't support chat or isn't available for key
                # continue to next candidate
                # small delay in case of transient errors
                time.sleep(0.1)
                continue
        except Exception:
            # model construction failed; try next candidate
            continue

    return (None, None)

# Try to pick and initialize a model/chat on import
_SELECTED_MODEL_NAME = None
_model_and_chat = None
try:
    _SELECTED_MODEL_NAME, _model_and_chat = _pick_working_model()
except Exception:
    _SELECTED_MODEL_NAME, _model_and_chat = (None, None)

if not _SELECTED_MODEL_NAME:
    # don't crash import; allow ask_ai to return a useful error
    _SELECTED_MODEL_NAME = None

def ask_ai(prompt):
    """
    Send `prompt` to Gemini and return the response text.
    If no working model was found, returns an explanatory error string.
    """
    if not _SELECTED_MODEL_NAME:
        return ("❌ No working Gemini model found for this API key. "
                "Make sure your key is valid and you have access to at least one Gemini model. "
                "You can troubleshoot by calling the ListModels endpoint (see README).")

    try:
        # If we have the older model+chat tuple:
        if _model_and_chat and isinstance(_model_and_chat, tuple):
            model, chat = _model_and_chat
            # send the message and return text (trim whitespace)
            resp = chat.send_message(prompt)
            return resp.text.strip()
        # If using newer client (we returned model name only), fall back to client.models.generate_content
        if 'client' in globals():
            resp = client.models.generate_content(model=_SELECTED_MODEL_NAME, contents=prompt)
            return getattr(resp, "text", str(resp)).strip()
        return "❌ Unexpected runtime configuration."
    except Exception as e:
        # Return the raw exception to help debugging (you can log it instead in production)
        return f"❌ Error with Gemini API: {e}"
