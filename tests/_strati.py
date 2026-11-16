"""What tests/test_strati.py must know of P7M Extractor, the one part of the
layers' check that is the app's own (no fingerprint). test_strati.py is the
model's file, the same in every app, and reads these names. The shared
modules are not listed here: they are the manifest's (impronte/comune.json).
"""

TOOLKIT = ("gi",)

# The parts of the toolkit's library that show nothing, which app/ may
# import: none, the services of P7M Extractor are plain Python.
WINDOWLESS: tuple[str, ...] = ()

# every file of app/ may use them
WINDOWLESS_FILES: tuple[str, ...] = ()

# "file -> what it imports": "why it is still there, and when it goes".
# None: the list can only get shorter.
DEBTS: dict[str, str] = {}

# gui modules that do not import the toolkit, "file": "why it stays in gui".
# Frozen: none may be added (plain logic belongs in core, data or app).
GUI_WITHOUT_TOOLKIT: dict[str, str] = {}

# gui modules that are values and nothing else: none in P7M Extractor.
GUI_VALUES: set[str] = set()
