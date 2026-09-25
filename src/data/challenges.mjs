// The directory and resource mappings are deliberately explicit. Only listed
// downloads and Markdown-referenced images enter the production build.
export const challenges = [
  {
    slug: 'capture-the-system', title: 'Capture the System', directory: 'Capture The System', level: null, placement: '1st place',
    resources: [['v46.hex', 'V46 bot'], ['v46_lattice_viewer.py', 'Lattice viewer source']],
    explainer: { file: 'v46-lattice-viewer.html', title: 'V46 Visualiser', before: 'how-v46-works' },
  },
  {
    slug: 'expcalibur', title: 'EXPcalibur', directory: 'EXPcalibur', level: null, placement: '3rd place',
    resources: [['device-payloads.json', 'Device payloads'], ['registration-nonces.json', 'Registration nonces'], ['evidence/runner', 'Challenge runner'], ['evidence/build-bot.py', 'Build script'], ['evidence/bot-base.bin', 'Base bot'], ['evidence/bot-base.json', 'Build metadata'], ['evidence/final-bot.bin', 'Final bot'], ['evidence/canonical-graph.bin', 'Canonical graph'], ['evidence/trace-graph.py', 'Graph trace script'], ['evidence/graph-tokens.bin', 'Graph token context'], ['evidence/graph-input.bin', 'Graph input bank']],
    explainer: { file: 'expcalibur-live-trace.html', title: 'Recorded device trace', before: 'the-hidden-device' },
  },
  {
    slug: 'game-vault', title: 'Game Vault', directory: '9 - Game Vault', level: 9,
    resources: [['solve.py', 'Solve script'], ['check_console_logins.py', 'Console login checker']],
  },
  {
    slug: 'cmdwrap', title: 'cmdwrap', directory: '8 - cmdwrap', level: 8,
    resources: [['cmdwrap.exe', 'Original challenge binary'], ['solution/solve.py', 'Final solve script'], ['solution/scan_flag_memory.bin', 'Memory scan helper'], ['solution/predict_canary.py', 'Canary prediction script'], ['solution/override_catalog.py', 'Catalog override script'], ['solution/multiwrite_override.py', 'Multiwrite script'], ['dll/chain.dll', 'Chain module'], ['dll/flag_decode.dll', 'Flag decode module']],
  },
  {
    slug: 'omnitrix', title: 'Omnitrix', directory: '7 - Omnitrix', level: 7,
    resources: [['omnitrix', 'Original service binary'], ['Dockerfile', 'Challenge Dockerfile'], ['exploit.c', 'Exploit source'], ['solve.py', 'Solve script']],
  },
  {
    slug: 'provenance', title: 'Provenance', directory: '6 - Provenance', level: 6,
    resources: [['challenge.exe', 'Original challenge binary'], ['challenge.repaired.exe', 'Repaired binary'], ['solve.py', 'Solve script']],
  },
  {
    slug: 'trash-talk', title: 'Trash Talk', directory: '5 - Trash Talk', level: 5,
    resources: [['solve.py', 'Solve script'], ['hidden-target-b618a9cf.bin', 'Hidden target record B618'], ['hidden-target-ddfc445a.bin', 'Hidden target record DDFC'], ['hidden-target-e7979ed2.bin', 'Hidden target record E797']],
  },
  {
    slug: 'zygpt', title: 'ZyGPT', directory: '4 - ZyGPT', level: 4,
    resources: [['solve.py', 'Solve script'], ['show_maintenance_diagnostic.py', 'Diagnostic script'], ['verified_solution.json', 'Verified solution data']],
  },
  {
    slug: 'lion-city-layover', title: 'Lion City Layover', directory: '3 - Lion City Layover', level: 3,
    resources: [['singa_legacy.wasm', 'Original WebAssembly module'], ['solve.py', 'Solve script']],
  },
  {
    slug: 'my-printer-has-a-secret', title: 'My Printer has a Secret', directory: '2 - My Printer has a Secret', level: 2,
    resources: [['printer-secret.png', 'Original printed sheet'], ['printer-secret-part2.txt', 'Archive text']],
  },
  {
    slug: 'redacted', title: 'REDACTED', directory: '1 -🗃️ REDACTED', level: 1,
    resources: [['TISC-26-091-SINGULARITY.pdf', 'Original challenge PDF']],
  },
];
