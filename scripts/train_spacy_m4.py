"""
SPECTRE — Module 4: Custom spaCy Multi-Label Text Categorizer Training
Trains a semantic intent classifier to distinguish deceptive mobile UI strings
from legitimate application strings.
"""
from pathlib import Path
import random
import spacy
from spacy.tokens import DocBin
from spacy.training import Example

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = PROJECT_ROOT / "backend" / "models" / "spacy_textcat"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# 1. Representative Training Corpus (Lures vs Legitimate App Text)
TRAINING_DATA = [
    # --- URGENCY & COERCION ---
    ("Your mobile banking account will be suspended within 24 hours.", {"URGENCY": 1.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("SIM card deactivation warning: Update KYC immediately to retain incoming calls.", {"URGENCY": 1.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Immediate action needed: suspicious login attempt detected from an unknown device.", {"URGENCY": 1.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Warning! Critical security patch missing. Device at severe risk.", {"URGENCY": 1.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 1.0}),
    ("Your access has been temporarily restricted. Verify identity now to unblock.", {"URGENCY": 1.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),

    # --- FINANCIAL & CREDENTIAL HARVESTING ---
    ("Enter your 6-digit UPI PIN to claim your cashback refund.", {"URGENCY": 0.0, "FINANCIAL": 1.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Provide your ATM card number, expiry date, and CVV to complete KYC verification.", {"URGENCY": 0.0, "FINANCIAL": 1.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Please enter the One Time Password (OTP) received on your registered phone number.", {"URGENCY": 0.0, "FINANCIAL": 1.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Confirm your netbanking username and transaction password to synchronize balance.", {"URGENCY": 0.0, "FINANCIAL": 1.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Input your MPIN to unlock your wallet account and receive daily bonus.", {"URGENCY": 0.0, "FINANCIAL": 1.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),

    # --- PRIVILEGE TRAP & ACCESSIBILITY HIJACK ---
    ("Turn on Accessibility Service to allow battery optimization and speed boost.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 1.0, "MASQUERADE": 0.0}),
    ("Enable Device Administrator privilege to activate advanced security protection.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 1.0, "MASQUERADE": 0.0}),
    ("Grant 'Display over other apps' permission to enable seamless video overlay.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 1.0, "MASQUERADE": 0.0}),
    ("Please allow notification listener access so the application can clean junk files.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 1.0, "MASQUERADE": 0.0}),
    ("Grant permission to install unknown apps from this source to continue.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 1.0, "MASQUERADE": 0.0}),

    # --- UPDATE MASQUERADE ---
    ("A critical Google Play Store update is required to run this utility.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 1.0}),
    ("WhatsApp security update detected. Tap here to upgrade to latest version.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 1.0}),
    ("Flash Player plugin out of date. Install patch to view content.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 1.0}),
    ("System framework update required for high definition video rendering.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 1.0}),

    # --- BENIGN & LEGITIMATE UI (Zero Phishing Risk) ---
    ("Welcome to Period Tracker. Track your ovulation cycle and monthly symptoms.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Select your favorite background theme from settings.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("High score saved! Tap to play another round.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Weather forecast updated for your current city. Clear skies ahead.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Bluetooth device connected successfully. Audio stream ready.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Your account statement is available for download in PDF format.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Please rate our calculator app on Google Play if you enjoy using it.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
    ("Light candle by tapping the matchstick icon on the screen.", {"URGENCY": 0.0, "FINANCIAL": 0.0, "PRIVILEGE": 0.0, "MASQUERADE": 0.0}),
]


def train_spacy_textcat():
    print("[SPACY] Initializing blank English pipeline...")
    nlp = spacy.blank("en")

    # Add multi-label text categorizer
    textcat = nlp.add_pipe("textcat_multilabel")
    for label in ["URGENCY", "FINANCIAL", "PRIVILEGE", "MASQUERADE"]:
        textcat.add_label(label)

    # Convert training data into spaCy Examples
    examples = []
    for text, annotations in TRAINING_DATA:
        doc = nlp.make_doc(text)
        example = Example.from_dict(doc, {"cats": annotations})
        examples.append(example)

    # Initialize weights
    optimizer = nlp.initialize()

    print(f"[TRAIN] Training Text Categorizer on {len(TRAINING_DATA)} semantic samples...")
    for epoch in range(35):
        random.shuffle(examples)
        losses = {}
        for example in examples:
            nlp.update([example], sgd=optimizer, losses=losses)
        if (epoch + 1) % 5 == 0:
            print(f"  Epoch {epoch+1:2d} | Loss: {losses.get('textcat_multilabel', 0.0):.4f}")

    # Export compiled pipeline
    nlp.to_disk(MODEL_DIR)
    print(f"\n[EXPORT] Trained spaCy model exported to: {MODEL_DIR}")

    # Validation check
    print("\n--- VALIDATION INFERENCE TEST ---")
    test_texts = [
        "Your bank profile is locked. Please input your transaction PIN to unfreeze.",
        "Tap to light the virtual candle and change flame color.",
        "Urgent: grant accessibility access to prevent system slowdown.",
    ]
    for sample in test_texts:
        doc = nlp(sample)
        top_cats = {k: round(v, 3) for k, v in doc.cats.items() if v > 0.4}
        print(f"Input: '{sample}'")
        print(f"  -> Predictions: {top_cats if top_cats else 'BENIGN / NORMAL'}\n")


if __name__ == "__main__":
    train_spacy_textcat()